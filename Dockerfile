ARG ARCH="amd64"
ARG OS="linux"
FROM quay.io/prometheus/busybox-${OS}-${ARCH}:latest
LABEL maintainer="The Prometheus Authors <prometheus-developers@googlegroups.com>"
LABEL org.opencontainers.image.source="https://github.com/cmetech/alertmanager"
LABEL org.oscar.alertmanager.page-contract="2"
LABEL org.oscar.alertmanager.silence-mutation-auth="1"

ARG ARCH="amd64"
ARG OS="linux"
COPY .build/${OS}-${ARCH}/amtool       /bin/amtool
COPY .build/${OS}-${ARCH}/alertmanager /bin/alertmanager
COPY examples/ha/alertmanager.yml      /etc/alertmanager/alertmanager.yml

RUN mkdir -p /data /home && \
    chown -R nobody:nobody /etc/alertmanager /data /home && \
    chmod -R g+w /data

USER       nobody
EXPOSE     9093
VOLUME     [ "/data" ]
WORKDIR    /
ENTRYPOINT [ "/bin/alertmanager" ]
CMD        [ "--config.file=/etc/alertmanager/alertmanager.yml", \
             "--storage.path=/data" ]
