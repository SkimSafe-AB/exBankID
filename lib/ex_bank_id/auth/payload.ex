defmodule ExBankID.Auth.Payload do
  @moduledoc """
  Provides the struct used when initiating a authentication
  """
  defstruct [:endUserIp, :returnUrl, :returnRisk, :userVisibleData, :userVisibleDataFormat, :userNonVisibleData, ]

  import ExBankID.PayloadHelpers

  @type reason :: binary()

  @spec new(binary, Keyword.t()) ::
          {:error, reason}
          | %__MODULE__{endUserIp: binary, returnUrl: binary(), returnRisk: boolean(), userVisibleData: binary(), userVisibleDataFormat: binary(), userNonVisibleData: binary() | nil}
  @doc """
  Returns a Payload struct containing the given ip address and personal number.

  ## Examples
      iex> ExBankID.Auth.Payload.new("1.1.1.1")
      %ExBankID.Auth.Payload{endUserIp: "1.1.1.1"}

      iex> ExBankID.Auth.Payload.new("qwerty")
      {:error, "Invalid ip address: qwerty"}

      iex> ExBankID.Auth.Payload.new("1.1.1.1", [personal_number: "190000000000"])
      %ExBankID.Auth.Payload{endUserIp: "1.1.1.1", personalNumber: "190000000000"}

      iex> ExBankID.Auth.Payload.new("1.1.1.1", [personal_number: "Not a personal number"])
      {:error, "Invalid personal number: Not a personal number"}

      iex> ExBankID.Auth.Payload.new("1.1.1.1", [requirement: %{allowFingerprint: :false}])
      %ExBankID.Auth.Payload{endUserIp: "1.1.1.1", requirement: %{allowFingerprint: :false}}

      iex> ExBankID.Auth.Payload.new("1.1.1.1", [requirement: %{cardReader: "class2", tokenStartRequired: :false}])
      %ExBankID.Auth.Payload{endUserIp: "1.1.1.1", requirement: %{cardReader: "class2", tokenStartRequired: :false}}

      iex> ExBankID.Auth.Payload.new("1.1.1.1", [requirement: %{issuerCn: ["Nordea CA for Smartcard users 12", "Nordea CA for Softcert users 13"] }])
      %ExBankID.Auth.Payload{endUserIp: "1.1.1.1", requirement: %{issuerCn: ["Nordea CA for Smartcard users 12", "Nordea CA for Softcert users 13"]}}

      iex> ExBankID.Auth.Payload.new("1.1.1.1", [requirement: %{certificatePolicies: ["1.2.752.78.1.2", "1.2.752.78.*", "1.2.752.78.1.*"] }])
      %ExBankID.Auth.Payload{endUserIp: "1.1.1.1", requirement: %{certificatePolicies: ["1.2.752.78.1.2", "1.2.752.78.*", "1.2.752.78.1.*"] }}

      iex> ExBankID.Auth.Payload.new("1.1.1.1", [requirement: %{notRealRequirement: ["shouldFail"]}])
      {:error, "Invalid requirement"}
  """
  def new(ip_address, opts \\ []) when is_binary(ip_address) and is_list(opts) do
    with {:ok, ip_address} <- check_ip_address(ip_address),
         {:ok, return_url} <- check_url(Keyword.get(opts, :return_url)),
         {:ok, return_risk} <- {:ok, Keyword.get(opts, :return_risk)},
         {:ok, user_visible_data} <- check_string(Keyword.get(opts, :user_visible_data)),
         {:ok, user_visible_data_format} <- check_string(Keyword.get(opts, :user_visible_data_format)),
         {:ok, user_non_visible_data} <- check_string(Keyword.get(opts, :user_non_visible_data))
      do
      %__MODULE__{
        endUserIp: ip_address,
        returnUrl: return_url,
        returnRisk: return_risk,
        userVisibleData: user_visible_data,
        userVisibleDataFormat: user_visible_data_format,
        userNonVisibleData: user_non_visible_data 
      } |> Map.from_struct() |> Enum.reject( fn {_, v} -> v == nil end ) |> Enum.into(%{})
    end
  end
end
