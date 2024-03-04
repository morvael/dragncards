defmodule DragnCardsGame.Evaluate.Functions.GET_CARD do
  alias DragnCardsGame.Evaluate
  @moduledoc """
  Handles the 'GET_CARD' operation in the DragnCardsGame evaluation process.
  """

  @doc """
  Executes the 'GET_CARD' operation with the given arguments.

  ## Parameters

    - `args`: The arguments required for the 'GET_CARD' operation.

  ## Returns

  The result of the 'GET_CARD' operation.
  """
  def execute(game, code, trace) do
    card_id = Evaluate.evaluate(game, ["GET_CARD_ID", Enum.at(code,1), Enum.at(code,2), Enum.at(code,3)], trace ++ ["get_card_id"])
    if card_id do Evaluate.evaluate(game, "$GAME.cardById.#{card_id}", trace) else nil end
  end


end