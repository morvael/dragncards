defmodule DragnCardsWeb.RoomChannel do
  @moduledoc """
  This channel will handle individual game rooms.
  """
  use DragnCardsWeb, :channel
  alias DragnCardsGame.{GameUIServer, GameUI}
  alias DragnCardsChat.{ChatMessage}
  alias DragnCards.Users
  intercept ["send_update", "send_state"]

  require Logger


  def join("room:" <> room_slug, _payload, %{assigns: %{user_id: _user_id}} = socket) do

    socket =
      socket
      |> assign(:room_slug, room_slug)


    send(self(), :after_join)
    {:ok, socket}
  end

  def handle_info(:after_join, %{assigns: %{room_slug: room_slug, user_id: user_id}, transport_pid: pid} = socket) do
    GameUIServer.add_player_to_room(room_slug, user_id, pid)
    state = GameUIServer.state(room_slug)
    client_state = client_state(socket)
    if state["sockets"] != nil do
      broadcast!(socket, "users_changed", state["sockets"])
    end
    if client_state != nil do
      push(socket, "current_state", client_state(socket))
    end

    {:noreply, socket}
  end

  def handle_info({:plugin_repo_update, files}, socket) do

    push(socket, "plugin_repo_update", %{"files" => files})
    {:noreply, socket}
  end

  def handle_info({:send_alert, payload}, socket) do
    broadcast!(socket, "send_alert", payload)
    {:noreply, socket}
  end

  def handle_info(msg, socket) do
    Logger.warn("Unexpected message received in handle_info: #{inspect(msg)}")
    {:noreply, socket}
  end

  def handle_in("request_state", _payload, %{assigns: %{room_slug: room_slug}} = socket) do
    client_state = client_state(socket)
    push(socket, "current_state", client_state)
    {:reply, {:ok, "request_state"}, socket}
  end

  def handle_in(
    "game_action",
    %{
      "action" => action,
      "options" => options,
      "timestamp" => _timestamp,
    },
    %{assigns: %{room_slug: room_slug, user_id: user_id}} = socket
  ) do

    old_state = GameUIServer.state(room_slug)
    old_replay_step = old_state["replayStep"]
    GameUIServer.game_action(room_slug, user_id, action, options)

    new_state = GameUIServer.state(room_slug)

    # If round changed, save replay
    if get_in(new_state, ["game", "roundNumber"]) != get_in(old_state, ["game", "roundNumber"]) do
      IO.puts("Round changed, saving replay, user_id: #{user_id}")
      save_replay(socket, room_slug, user_id, options)
      # {alert_text, alert_level} = case GameUI.save_replay(new_state, user_id, options) do
      #   {:ok, message} -> {message, "success"}
      #   {:error, message} -> {message, "error"}
      #   _ -> {"Failed to save game.", "error"}
      # end

      # notify_alert(socket, room_slug, user_id, %{
      #   "level" => alert_level,
      #   "text" => alert_text
      # })
    end

    notify_update(socket, room_slug, user_id, old_state)

    {:reply, {:ok, "game_action"}, socket}
  end

  def handle_in(
    "save_replay",
    %{
      "options" => options,
      "timestamp" => _timestamp,
    },
    %{assigns: %{room_slug: room_slug, user_id: user_id}} = socket
  ) do
    IO.puts("Save replay, user_id: #{user_id}")
    save_replay(socket, room_slug, user_id, options)
    {:reply, {:ok, "save_replay"}, socket}
  end

  def handle_in(
    "step_through",
    %{
      "options" => options,
    },
    %{assigns: %{room_slug: room_slug, user_id: user_id}} = socket
  ) do
    old_state = GameUIServer.state(room_slug)
    old_replay_step = old_state["replayStep"]
    old_game = old_state["game"]
    GameUIServer.step_through(room_slug, options)
    new_state = GameUIServer.state(room_slug)
    new_replay_step = new_state["replayStep"]
    new_game = new_state["game"]
    delta = GameUI.get_delta(old_game, new_game)

    payload = %{
      "oldReplayStep" => old_state["replayStep"],
      "newReplayStep" => new_state["replayStep"],
      "delta" => delta
    }
    broadcast!(socket, "go_to_replay_step", payload)

    {:reply, {:ok, "game_action"}, socket}
  end

  def handle_in(
    "set_seat",
    %{
      "player_i" => player_i,
      "new_user_id" => new_user_id,
      "timestamp" => _timestamp,
    },
    %{assigns: %{room_slug: room_slug, user_id: user_id}} = socket
  ) do

    old_state = GameUIServer.state(room_slug)
    old_replay_step = old_state["replayStep"]
    old_game = old_state["game"]
    GameUIServer.set_seat(room_slug, user_id, player_i, new_user_id)
    new_state = GameUIServer.state(room_slug)

    if new_state["playerInfo"] != nil do
      broadcast!(socket, "seats_changed", new_state["playerInfo"])
    end

    notify_update(socket, room_slug, user_id, old_state)

    {:reply, :ok, socket}
  end

  def handle_in(
    "set_spectator",
    %{
      "user_id" => spectator_user_id,
      "value" => value,
    },
    %{assigns: %{room_slug: room_slug, user_id: user_id}} = socket
  ) do

    spectator_alias = Users.get_alias(spectator_user_id)
    GameUIServer.set_spectator(room_slug, user_id, spectator_user_id, value)
    state = GameUIServer.state(room_slug)

    broadcast!(socket, "spectators_changed", state["spectators"])

    message = if value do
      "#{spectator_alias} is now an omniscient spectator and has the power to see facedown cards."
    else
      "#{spectator_alias} is no longer an omniscient spectator."
    end

    payload = %{
      "level" => "info",
      "text" => message
    }
    notify_alert(socket, room_slug, user_id, payload)

    {:reply, :ok, socket}
  end

  def handle_in(
    "send_alert",
    %{
      "message" => message,
    },
    %{assigns: %{room_slug: room_slug, user_id: user_id}} = socket
  ) do

    payload = %{
      "level" => "info",
      "text" => message
    }
    notify_alert(socket, room_slug, user_id, payload)

    {:reply, :ok, socket}
  end

  def handle_in(
    "reset_game",
    %{
      "options" => options,
    },
    %{assigns: %{room_slug: room_slug, user_id: user_id}} = socket
  ) do
    gameui = GameUIServer.state(room_slug)
    if options["save"] == true or options["save"] == nil do
      GameUI.save_replay(gameui, user_id, options)
    end
    GameUIServer.reset_game(room_slug, user_id)

    notify_state(socket, room_slug, user_id)

    {:reply, {:ok, "reset_game"}, socket}
  end

  def handle_in(
    "set_replay",
    %{
      "replay" => replay,
    },
    %{assigns: %{room_slug: room_slug, user_id: user_id}} = socket
  ) do

    GameUIServer.set_replay(room_slug, user_id, replay)

    notify_state(socket, room_slug, user_id)

    {:reply, {:ok, "set_replay"}, socket}
  end

  def handle_in(
    "close_room",
    %{
      "options" => options,
    },
    %{assigns: %{room_slug: room_slug, user_id: user_id}} = socket
  ) do
    gameui = GameUIServer.state(room_slug)
    GameUI.save_replay(gameui, user_id, options)
    GameUIServer.close_room(room_slug, user_id)

    notify_state(socket, room_slug, user_id)

    {:reply, :ok, socket}
  end

  def terminate({:normal, _payload}, socket) do
    on_terminate(socket)
  end

  def terminate({:shutdown, :left}, socket) do
    on_terminate(socket)
  end

  def terminate({:shutdown, :closed}, socket) do
    on_terminate(socket)
  end

  def terminate(_reason, socket) do
    on_terminate(socket)
  end

  defp on_terminate(%{assigns: %{room_slug: room_slug, user_id: user_id}, transport_pid: pid} = socket) do
    GameUIServer.remove_player_from_room(room_slug, user_id, pid)
    state = GameUIServer.state(room_slug)
    if state["sockets"] != nil do
      broadcast!(socket, "users_changed", state["sockets"])
    end
  end

  defp save_replay(socket, room_slug, user_id, options) do
    new_state = GameUIServer.state(room_slug)
    {alert_text, alert_level} = try do
      case GameUI.save_replay(new_state, user_id, options) do
        {:ok, message} -> {message, "success"}
        {:error, message} -> {message, "error"}
        _ -> {"Failed to save game.", "error"}
      end
    rescue
      _ ->
      {"Failed to save game.", "error"}
    end

    notify_alert(socket, room_slug, user_id, %{
      "level" => alert_level,
      "text" => alert_text
    })
  end

  defp notify_update(socket, room_slug, user_id, old_gameui) do

    GameUIServer.process_update(room_slug, user_id, old_gameui)
    new_gameui = GameUIServer.state(room_slug)
    delta = Enum.at(new_gameui["deltas"], -1)

    payload = %{
      "oldReplayStep" => old_gameui["replayStep"],
      "newReplayStep" => new_gameui["replayStep"],
      "delta" => delta
    }
    broadcast!(socket, "send_update", payload)

    {:noreply, socket}
  end

  defp notify_state(socket, room_slug, user_id) do

    triggered_by = user_id
    broadcast!(socket, "send_state", triggered_by)

    {:noreply, socket}
  end

  defp notify_alert(socket, room_slug, user_id, payload) do

    broadcast!(socket, "send_alert", payload)

    {:noreply, socket}
  end

  # Define the handle_out function for the intercepted event
  def handle_out("send_state", triggered_by, socket) do
    new_client_state = client_state(socket)
    if new_client_state != nil do
      push(socket, "current_state", new_client_state)
    end
    {:noreply, socket}
  end

  # Define the handle_out function for the intercepted event
  def handle_out("send_update", payload, socket) do
    new_client_update = client_update(payload, socket.assigns)
    if new_client_update != nil do
      push(socket, "state_update", new_client_update)
    end
    {:noreply, socket}
  end

  # Define the handle_out function for the intercepted event
  def handle_out("go_to_replay_step", payload, socket) do
    new_client_update = client_update(payload, socket.assigns)
    if new_client_update != nil do
      push(socket, "go_to_replay_step", new_client_update)
    end
    {:noreply, socket}
  end

  defp client_update(payload, assigns) do
    gameui = GameUIServer.state(assigns[:room_slug])
    player_n = GameUI.get_player_n_by_user_id(gameui, assigns[:user_id])

    payload
    |> Map.put("player_n", player_n)

  end

  # This is what part of the state gets sent to the client.
  # It can be used to transform or hide it before they get it.
  defp client_state(socket) do
    GameUIServer.state(socket.assigns[:room_slug])
  end
end
