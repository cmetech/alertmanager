module Utils.ActionNatural exposing (Natural, Positive, decodeNatural, decodePositive, encodeNatural, encodePositive)

import Json.Decode as Decode exposing (Decoder)
import Json.Encode as Encode


{-| The wire uses integer JSON tokens. Elm decodes these through JavaScript
numbers. Keep identity and revision values inside the consecutive integer range.
-}
type Natural
    = Natural Int


type Positive
    = Positive Int


integer : Int -> (Int -> a) -> Decoder a
integer minimum construct =
    Decode.int
        |> Decode.andThen
            (\value ->
                if value >= minimum && value <= 9007199254740991 then
                    Decode.succeed (construct value)

                else
                    Decode.fail "Native action integer exceeds the field's exact Elm range"
            )


decodeNatural : Decoder Natural
decodeNatural =
    integer 0 Natural


decodePositive : Decoder Positive
decodePositive =
    integer 1 Positive


encodeNatural : Natural -> Encode.Value
encodeNatural (Natural value) =
    Encode.int value


encodePositive : Positive -> Encode.Value
encodePositive (Positive value) =
    Encode.int value
