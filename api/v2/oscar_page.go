// Copyright The Prometheus Authors
// Licensed under the Apache License, Version 2.0.

package v2

import (
	"container/heap"
	"fmt"
	"net/url"
	"regexp"
	"slices"
	"sort"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/go-openapi/runtime/middleware"
	"github.com/prometheus/alertmanager/alert"
	models "github.com/prometheus/alertmanager/api/v2/models"
	ops "github.com/prometheus/alertmanager/api/v2/restapi/operations/alert"
	model "github.com/prometheus/common/model"
)

type pageCandidate struct {
	a                *alert.Alert
	status           alert.AlertStatus
	receivers        []string
	key, fingerprint string
	instant          time.Time
}
type pageHeap struct {
	rows          []pageCandidate
	desc, timeKey bool
}

func (h pageHeap) Len() int { return len(h.rows) }
func (h pageHeap) better(a, b pageCandidate) bool {
	cmp := strings.Compare(a.key, b.key)
	if h.timeKey {
		cmp = a.instant.Compare(b.instant)
	}
	if cmp == 0 {
		cmp = strings.Compare(a.fingerprint, b.fingerprint)
	}
	if h.desc {
		return cmp > 0
	}
	return cmp < 0
}
func (h pageHeap) Less(i, j int) bool { return h.better(h.rows[j], h.rows[i]) }
func (h pageHeap) Swap(i, j int)      { h.rows[i], h.rows[j] = h.rows[j], h.rows[i] }
func (h *pageHeap) Push(x any)        { h.rows = append(h.rows, x.(pageCandidate)) }
func (h *pageHeap) Pop() any          { n := len(h.rows); x := h.rows[n-1]; h.rows = h.rows[:n-1]; return x }

func (api *API) getOscarAlertsPageHandler(p ops.GetOscarAlertsPageParams) middleware.Responder {
	bad := func(err error) middleware.Responder {
		return ops.NewGetOscarAlertsPageBadRequest().WithPayload(err.Error())
	}
	q, err := url.ParseQuery(p.HTTPRequest.URL.RawQuery)
	if err != nil {
		return bad(err)
	}
	allowed := map[string]bool{"page": true, "perPage": true, "column": true, "order": true, "active": true, "silenced": true, "inhibited": true, "unprocessed": true, "receiver": true, "severity": true, "quick_search": true, "filter": true, "receiver_matchers": true}
	for k, v := range q {
		if !allowed[k] || ((k != "filter" && k != "receiver_matchers") && (len(v) != 1 || v[0] == "")) {
			return bad(fmt.Errorf("invalid query parameter %q", k))
		}
	}
	integer := func(name string, def, max int) (int, error) {
		s := q.Get(name)
		if s == "" {
			return def, nil
		}
		for _, r := range s {
			if r < '0' || r > '9' {
				return 0, fmt.Errorf("invalid %s", name)
			}
		}
		n, e := strconv.Atoi(s)
		if e != nil || n < 1 || n > max {
			return 0, fmt.Errorf("invalid %s", name)
		}
		return n, nil
	}
	page, e := integer("page", 1, 50000)
	if e != nil {
		return bad(e)
	}
	per, e := integer("perPage", 10, 100)
	if e != nil {
		return bad(e)
	}
	if page > int(^uint(0)>>1)/per {
		return bad(fmt.Errorf("page overflow"))
	}
	k := page * per
	boolParam := func(name string) (bool, error) {
		switch q.Get(name) {
		case "", "true":
			return true, nil
		case "false":
			return false, nil
		default:
			return false, fmt.Errorf("invalid %s", name)
		}
	}
	active, e := boolParam("active")
	if e != nil {
		return bad(e)
	}
	silenced, e := boolParam("silenced")
	if e != nil {
		return bad(e)
	}
	inhibited, e := boolParam("inhibited")
	if e != nil {
		return bad(e)
	}
	if _, e = boolParam("unprocessed"); e != nil {
		return bad(e)
	}
	column := q.Get("column")
	if column == "" {
		column = "startsAt"
	}
	switch column {
	case "startsAt", "starts_at", "ends_at", "alertname", "severity", "instance", "summary", "alert_status", "fingerprint":
	default:
		return bad(fmt.Errorf("invalid column"))
	}
	order := q.Get("order")
	if order == "" {
		order = "desc"
	}
	if order != "asc" && order != "desc" {
		return bad(fmt.Errorf("invalid order"))
	}
	if utf8.RuneCountInString(q.Get("quick_search")) > 200 {
		return bad(fmt.Errorf("quick_search too long"))
	}
	matchers, e := parseFilter(q["filter"])
	if e != nil {
		return bad(e)
	}
	rm, e := parseFilter(q["receiver_matchers"])
	if e != nil {
		return bad(e)
	}
	var receiver *regexp.Regexp
	if s := q.Get("receiver"); s != "" {
		receiver, e = regexp.Compile("^(?:" + s + ")$")
		if e != nil {
			return bad(e)
		}
	}
	api.mtx.RLock()
	route := api.route
	labels := api.receiverLabelsMap()
	statusFn := api.setAlertStatus
	api.mtx.RUnlock()
	ctx := p.HTTPRequest.Context()
	iter := api.alerts.GetPending()
	defer iter.Close()
	h := &pageHeap{desc: order == "desc", timeKey: column == "startsAt" || column == "starts_at" || column == "ends_at"}
	now := time.Now()
	total := 0
	severity := strings.ToLower(q.Get("severity"))
	search := strings.ToLower(q.Get("quick_search"))
	for {
		select {
		case <-ctx.Done():
			return ops.NewGetOscarAlertsPageInternalServerError().WithPayload(ctx.Err().Error())
		case item, ok := <-iter.Next():
			if !ok {
				if err = iter.Err(); err != nil {
					return ops.NewGetOscarAlertsPageInternalServerError().WithPayload(err.Error())
				}
				goto done
			}
			a := item.Data
			if (!a.EndsAt.IsZero() && a.EndsAt.Before(now)) || !alertMatchesFilterLabels(&a.Alert, matchers) {
				continue
			}
			routes := route.Match(a.Labels)
			receivers := make([]string, 0, len(routes))
			for _, r := range routes {
				receivers = append(receivers, r.RouteOpts.Receiver)
			}
			if receiver != nil && !slices.ContainsFunc(receivers, receiver.MatchString) {
				continue
			}
			if len(rm) > 0 && !receiversMatchLabels(receivers, rm, labels) {
				continue
			}
			status := predictAlertStatus(ctx, statusFn, a)
			if (!active && status.State == alert.AlertStateActive) || (!silenced && len(status.SilencedBy) > 0) || (!inhibited && len(status.InhibitedBy) > 0) {
				continue
			}
			if severity != "" && strings.ToLower(string(a.Labels["severity"])) != severity {
				continue
			}
			fp := a.Fingerprint().String()
			if search != "" && !strings.Contains(strings.ToLower(string(a.Labels["alertname"])), search) && !strings.Contains(strings.ToLower(string(status.State)), search) && !strings.Contains(strings.ToLower(string(a.Labels["severity"])), search) && !strings.Contains(strings.ToLower(string(a.Annotations["summary"])), search) && !strings.Contains(strings.ToLower(fp), search) {
				continue
			}
			c := pageCandidate{a: a, status: status, receivers: receivers, fingerprint: fp}
			switch column {
			case "startsAt", "starts_at":
				c.instant = a.StartsAt.UTC().Truncate(time.Millisecond)
			case "ends_at":
				c.instant = a.EndsAt.UTC().Truncate(time.Millisecond)
			case "summary":
				c.key = strings.ToLower(string(a.Annotations["summary"]))
			case "alert_status":
				c.key = strings.ToLower(string(status.State))
			case "fingerprint":
				c.key = strings.ToLower(fp)
			default:
				c.key = strings.ToLower(string(a.Labels[model.LabelName(column)]))
			}
			total++
			if h.Len() < k {
				heap.Push(h, c)
			} else if h.better(c, h.rows[0]) {
				h.rows[0] = c
				heap.Fix(h, 0)
			}
		}
	}
done:
	if err = ctx.Err(); err != nil {
		return ops.NewGetOscarAlertsPageInternalServerError().WithPayload(err.Error())
	}
	start := (page - 1) * per
	records := models.GettableAlerts{}
	if start < len(h.rows) {
		sort.Slice(h.rows, func(i, j int) bool { return h.better(h.rows[i], h.rows[j]) })
		end := min(start+per, len(h.rows))
		for _, c := range h.rows[start:end] {
			records = append(records, AlertToOpenAPIAlert(c.a, c.status, c.receivers, nil))
		}
	}
	count := int64(total)
	pages := int64((total + per - 1) / per)
	return ops.NewGetOscarAlertsPageOK().WithPayload(&models.OscarAlertPage{Records: records, TotalRecords: &count, TotalPages: &pages})
}
