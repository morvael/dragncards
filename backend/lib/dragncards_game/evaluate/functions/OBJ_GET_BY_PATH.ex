defmodule DragnCardsGame.Evaluate.Functions.OBJ_GET_BY_PATH do
  alias DragnCardsGame.Evaluate
  @moduledoc """
  Handles the 'OBJ_GET_BY_PATH' operation in the DragnCardsGame evaluation process.
  """

  @doc """
  Executes the 'OBJ_GET_BY_PATH' operation with the given arguments.

  ## Parameters

    - `args`: The arguments required for the 'OBJ_GET_BY_PATH' operation.

  ## Returns

  The result of the 'OBJ_GET_BY_PATH' operation.
  """
  def execute(game, code, trace) do
    map = Evaluate.evaluate(game, Enum.at(code,1), trace ++ ["map"])
    path = Evaluate.evaluate(game, Enum.at(code,2), trace ++ ["path"])
    Enum.reduce(Enum.with_index(path), map, fn({pathi, index}, acc) ->
      cond do
        pathi == nil ->
          raise "Tried to access nil in path #{inspect(path)}."
        String.starts_with?(pathi, "[") and String.ends_with?(pathi, "]") ->
          int_str = Evaluate.evaluate(game, String.slice(pathi,1..-2), trace ++ ["index #{index}"])
          int = Evaluate.convert_to_integer(int_str)
          if acc == nil do
            raise "Tried to access index #{int} on a null array."
          end
          if not is_list(acc) do
            raise "Tried to access index #{int} on a non-array object."
          end
          if Enum.count(acc) <= int do
            raise "Tried to access index #{int} on an array of length #{Enum.count(acc)}."
          end
          Enum.at(acc, int)
        pathi == "currentFace" ->
          current_side = if acc["currentSide"] == nil do
            raise "Tried to access currentFace on an object where currentSide is null."
          else
            acc["currentSide"]
          end
          sides = if acc["sides"] == nil do
            raise "Tried to access sides on a non-card object."
          else
            acc["sides"]
          end
          if sides[current_side] == nil do
            raise "Tried to access side #{current_side} on an object with sides #{inspect(Map.keys(sides))}."
          else
            sides[current_side]
          end
        pathi == "stackParentCard" ->
          game["cardById"][acc["stackParentCardId"]]
        pathi == "parentCardIds" ->
          # Make sure there is a stackIds key
          if Map.has_key?(acc, "stackIds") do
            # Get the stackIds
            stack_ids = acc["stackIds"]
            # Return a list of the parent card ids
            Enum.map(stack_ids, fn(stack_id) ->
              # Get the stack
              stack = game["stackById"][stack_id]
              # Get the parent card id
              if stack == nil do
                raise "Tried to access parentCardIds but one of the stacks is null."
              end
              Enum.at(stack["cardIds"], 0)
            end)
          else
            raise "Tried to access parentCardIds on a non-group object."
          end
        pathi == "parentCards" ->
          # Make sure there is a stackIds key
          if Map.has_key?(acc, "stackIds") do
            # Get the stackIds
            stack_ids = acc["stackIds"]
            # Return a list of the parent card ids
            Enum.map(stack_ids, fn(stack_id) ->
              # Get the stack
              stack = game["stackById"][stack_id]
              # Get the parent card id
              card_id = Enum.at(stack["cardIds"], 0)
              game["cardById"][card_id]
            end)
          else
            raise "Tried to access parentCards on a non-group object."
          end
        acc == nil ->
          nil
        Map.has_key?(acc, pathi) ->
          Map.get(acc, Evaluate.evaluate(game, pathi, trace ++ ["key #{index}"]))
        true ->
          nil
          #raise "Tried to access #{pathi} on an object that doesn't have that key. Only keys are #{Map.keys(acc)}. #{inspect(trace)}"
      end
    end)
  end




end