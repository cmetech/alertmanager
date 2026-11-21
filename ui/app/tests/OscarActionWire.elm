module OscarActionWire exposing (suite)

import Data.OscarActionConflict as Conflict
import Data.OscarActionRequest as Request
import Data.OscarEpisodeRef as Ref
import Data.OscarPolicyBinding as Binding
import Expect
import Json.Decode as Decode
import Json.Encode as Encode
import Test exposing (Test, describe, test)


reference : String -> String
reference generation =
    """{"authority_id":"11111111-1111-4111-8111-111111111112","episode_id":"11111111-1111-4111-8111-111111111113","generation":""" ++ generation ++ ""","variant_revision":1}"""


suite : Test
suite =
    let
        body =
            """{"version":1,"operation_id":"11111111-1111-4111-8111-111111111111","episode_ref":""" ++ reference "1" ++ ""","kind":"acknowledge","target_scope":[],"actor":{"kind":"operator","id":"alice"},"policy_binding":null,"target_severity":null}"""
    in
    describe "Native action wire"
        [ test "operator null fields survive encoding" <|
            \() ->
                Decode.decodeString Request.decoder body
                    |> Result.map (Request.encoder >> Encode.encode 0)
                    |> Result.andThen (Decode.decodeString (Decode.map2 Tuple.pair (Decode.field "policy_binding" (Decode.null ())) (Decode.field "target_severity" (Decode.null ()))))
                    |> Expect.equal (Ok ( (), () ))
        , test "required nullable fields must be present" <|
            \() ->
                String.replace ""","target_severity":null""" "" body
                    |> Decode.decodeString Request.decoder
                    |> Expect.err
        , test "unrepresentable episode IDs fail closed" <|
            \() ->
                Decode.decodeString Ref.decoder (reference "9007199254740993")
                    |> Expect.err
        , test "episode generations must be positive" <|
            \() ->
                Decode.decodeString Ref.decoder (reference "0")
                    |> Expect.err
        , test "policy revision zero survives a non-null binding" <|
            \() ->
                Decode.decodeString Binding.decoder """{"binding_id":"11111111-1111-4111-8111-111111111112","revision_id":"11111111-1111-4111-8111-111111111113","cancellation_generation":0}"""
                    |> Result.map Binding.encoder
                    |> Result.andThen (Decode.decodeValue (Decode.field "cancellation_generation" Decode.int))
                    |> Expect.equal (Ok 0)
        , test "both execute conflict forms preserve the available identity" <|
            \() ->
                [ """{"reason":"ACTION_RECONCILIATION_REQUIRED"}"""
                , """{"reason":null,"operation_id":"11111111-1111-4111-8111-111111111111","state":"held"}"""
                ]
                    |> List.map (Decode.decodeString Conflict.decoder >> Result.map .operationId)
                    |> Expect.equal [ Ok Nothing, Ok (Just "11111111-1111-4111-8111-111111111111") ]
        , test "largest exactly supported generation is preserved" <|
            \() ->
                Decode.decodeString Ref.decoder (reference "9007199254740991")
                    |> Result.map (Ref.encoder >> Encode.encode 0)
                    |> Result.map (String.contains "9007199254740991")
                    |> Expect.equal (Ok True)
        ]
