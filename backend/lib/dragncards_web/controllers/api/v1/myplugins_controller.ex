defmodule DragnCardsWeb.MyPluginsController do
  use DragnCardsWeb, :controller
  import Ecto.Query

  alias DragnCards.{Plugins, Plugins.Plugin, Repo}

  action_fallback DragnCardsWeb.FallbackController

  def show(conn, %{"id" => user_id}) do
    IO.puts("here")
    # Faster to gather all columns except game_json

    my_plugins = if user_id != nil and user_id != "undefined" do
      query = from Plugin,
        order_by: [desc: :updated_at],
        where: [author_id: ^user_id],
         select: [
          :id,
          :author_id,
          :name,
          :version,
          :num_favorites,
          :public,
          :updated_at
        ]
      Repo.all(query)
    else
      []
    end
    #IO.inspect(my_plugins)
    my_plugins = Enum.reduce(my_plugins, [], fn(plugin, acc) ->
      acc ++ [Map.from_struct(plugin) |> Map.delete(:__meta__)]
    end)
    json(conn, %{my_plugins: my_plugins})
  end

  # Create: Create plugin
  @spec create(Conn.t(), map()) :: Conn.t()
  #def create(conn, %{"user" => user}) do
  def create(conn, %{"plugin" => plugin_params}) do
    IO.puts("plugin create 1")
    IO.inspect(plugin_params)
    case Plugins.create_plugin(plugin_params) do
      {:ok, struct} ->
        conn
        |> json(%{success: %{message: "Plugin created successfully"}})
      {:error, changeset} ->
        IO.puts("ERRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRROR")
        IO.inspect(changeset)
        conn
        |> json(%{error: %{message: "Plugin creation failed"}})
    end
  end


  # Update: Update plugin
  @spec update(Conn.t(), map()) :: Conn.t()
  def update(conn, %{"plugin" => plugin_params}) do
    plugin = Plugins.get_plugin!(plugin_params["id"])
    updates = %{
      "game_def" => plugin_params["game_def"] || plugin.game_def,
      "card_db" => plugin_params["card_db"] || plugin.card_db,
      "public" => plugin_params["public"],
      "version" => plugin.version + 1
    }
    case Plugins.update_plugin(plugin, plugin_params) do
      {:ok, struct} ->
        conn
        |> json(%{success: %{message: "Plugin updated successfully"}})
      {:error, changeset} ->
        conn
        |> json(%{error: %{message: "Plugin update failed"}})
      end
  end


  # Update: Update plugin
  @spec delete(Conn.t(), map()) :: Conn.t()
  def delete(conn, %{"id" => plugin_id}) do
    IO.puts("conn")
    IO.inspect(conn)
    user = Pow.Plug.current_user(conn)
    #plugin = Repo.get(Plugin, plugin_id)
    plugin = Repo.one(from p in Plugin, select: [:plugin_id], where: p.id == ^plugin_id)
    IO.puts("plugin to delete")
    IO.inspect(plugin)
    plugin_id = plugin.plugin_id
    user_id = user.id
    user_alias = user.alias
    {rows_deleted, _} = from(x in Plugin, where: x.plugin_id == ^plugin_id and x.author_user_id == ^user_id) |> Repo.delete_all
    IO.puts("rows_deleted")
    IO.inspect(rows_deleted)
    conn
    |> json(%{success: %{message: "Updated settings"}})
  end
end