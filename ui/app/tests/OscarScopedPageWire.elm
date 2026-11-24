module OscarScopedPageWire exposing (suite)

import Data.OscarScopedPageRequest as Request
import Dict
import Expect
import Json.Decode as Decode
import Test exposing (Test, describe, test)


suite : Test
suite =
    describe "Scoped request round trip"
        (List.map roundTrip [ Nothing, Just "and", Just "or" ])


roundTrip : Maybe String -> Test
roundTrip logic =
    test ("equals and isAnyOf with logic " ++ Maybe.withDefault "omitted" logic) <|
        \() ->
            let
                logicField =
                    Maybe.withDefault "" (Maybe.map (\value -> "\"logicOperator\":\"" ++ value ++ "\",") logic)

                body =
                    """{"version":1,"query":{},"scope":{"unrestricted":false,"allow":[{"""
                        ++ logicField
                        ++ """"items":[{"field":"label:service","operator":"equals","value":"café "},{"field":"label:env","operator":"isAnyOf","value":["prod","dev"]}]}],"deny":[]}}"""

                item index decoder =
                    Decode.field "items" <| Decode.index index <| Decode.map3 (\field op value -> ( field, op, value )) (Decode.field "field" Decode.string) (Decode.field "operator" Decode.string) (Decode.field "value" decoder)

                logicDecoder =
                    Decode.dict Decode.value
                        |> Decode.andThen
                            (\fields ->
                                if Dict.member "logicOperator" fields then
                                    Decode.map Just (Decode.field "logicOperator" Decode.string)

                                else
                                    Decode.succeed Nothing
                            )

                groupDecoder =
                    Decode.map3 (\op scalar choices -> ( op, scalar, choices )) logicDecoder (item 0 Decode.string) (item 1 (Decode.list Decode.string))
            in
            Decode.decodeString Request.decoder body
                |> Result.map Request.encoder
                |> Result.andThen (Decode.decodeValue (Decode.at [ "scope", "allow" ] (Decode.index 0 groupDecoder)))
                |> Expect.equal (Ok ( logic, ( "label:service", "equals", "café " ), ( "label:env", "isAnyOf", [ "prod", "dev" ] ) ))
