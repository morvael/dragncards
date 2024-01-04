defmodule DragnCardsGame.Evaluate.Functions.FOR_EACH_VAL do
  alias DragnCardsGame.Evaluate
  @moduledoc """
  Handles the 'FOR_EACH_VAL' operation in the DragnCardsGame evaluation process.
  """

  @doc """
  Executes the 'FOR_EACH_VAL' operation with the given arguments.

  ## Parameters

    - `args`: The arguments required for the 'FOR_EACH_VAL' operation.

  ## Returns

  The result of the 'FOR_EACH_VAL' operation.
  """
  def execute(game, code, trace) do
    val_name = Enum.at(code, 1)
    list = Evaluate.evaluate(game, Enum.at(code, 2), trace ++ ["list"])
    function = Enum.at(code, 3)
    Enum.reduce(Enum.with_index(list), game, fn({val, index}, acc) ->
      acc = Evaluate.evaluate(acc, ["VAR", val_name, val], trace ++ ["index #{index}"])
      Evaluate.evaluate(acc, function, trace ++ ["index #{index}"])
    end)
    # # Delete local variable
    # game
    # |> put_in(["variables"], Map.delete(game["variables"], "#{val_name}-#{current_scope_index}"))
  end


end