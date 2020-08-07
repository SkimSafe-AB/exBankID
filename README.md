# exBankID
![license: MIT](https://img.shields.io/github/license/anfly0/exBankID)

## Introduction
exBankID is a simple stateless API-client for the Swedish BankID API.

__This is very much a work in progress! All help is more than welcome__

## Usage

```elixir
# Authenticate with ip address and optionally the personal number (12 digits)
iex> {:ok, authentication} ExBankID.auth("1.1.1.1", personal_number: "190000000000")
{:ok,
 %ExBankID.Auth.Response{
   autoStartToken: "3241031e-d849-4e3a-a662-1a36e65eff93",
   orderRef: "9b69419c-b3ac-4f7c-9796-bf54f1a4e40b",
   qrStartSecret: "c0846df5-f96d-49c0-9ef5-4126cd9376e9",
   qrStartToken: "3fb97679-98cb-42da-afe6-62aecbaaab7e"
 }}

# Collect the status of the initiated authentication ether with the orderRef
# or with the ExBankID.Auth.Response struct
iex> {:ok, collect_response} = ExBankID.collect("9b69419c-b3ac-4f7c-9796-bf54f1a4e40b")
{:ok,
 %ExBankID.Collect.Response{
   completionData: %ExBankID.Collect.CompletionData{
     cert: %{},
     device: %{},
     ocspResponse: nil,
     signature: nil,
     user: %ExBankID.Collect.User{
       givenName: nil,
       name: nil,
       personalNumber: nil,
       surname: nil
     }
   },
   hintCode: "outstandingTransaction",
   orderRef: "1fadf49f-c695-4bb3-869a-61aee9678009",
   status: "pending"
 }}

 #or
 iex> {:ok, collect_response} = ExBankID.collect(authentication) # Using ExBankID.Auth.Response struct
{:ok,
 %ExBankID.Collect.Response{
   completionData: %ExBankID.Collect.CompletionData{
     cert: %{},
     device: %{},
     ocspResponse: nil,
     signature: nil,
     user: %ExBankID.Collect.User{
       givenName: nil,
       name: nil,
       personalNumber: nil,
       surname: nil
     }
   },
   hintCode: "outstandingTransaction",
   orderRef: "1fadf49f-c695-4bb3-869a-61aee9678009",
   status: "pending"
 }}

 # When authentication is completed by the end user the fields in CompletionData will
 # be populated.

 #User signing a given message.
 iex> {:ok, sign} = ExBankID.sign(
                "1.1.1.1",
                "This will be displayed in the BankID app",
                personal_number: "190000000000",    # Optional
                user_non_visible_data: "Not displayed" # Optional
                )
{:ok,
 %ExBankID.Sign.Response{
   autoStartToken: "c7b67410-c376-4d27-9aff-f7e331082619",
   orderRef: "90b3816d-c1d3-4650-aa4d-26d9996160de",
   qrStartSecret: "f28787ec-a554-4db4-90c6-dd662dd249bc",
   qrStartToken: "c7a2373b-9a7a-470f-816f-0af0c3d82053"
 }}
# Collecting is done the same way as for a authentication.

# Canceling a sign or authentication
iex> {:ok, _} = ExBankID.cancel(authentication)
{:ok, %{}}

# Config - all functions in the ExBankID takes the following optional argument
# [url: "url to BankID API", cert_file: "/path/to/your/BankID/certificate.pem"]  

```