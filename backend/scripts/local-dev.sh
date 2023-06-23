#!/bin/bash

# Make sure hex is installed
mix local.hex --force

# Get deps
mix deps.get

# Do any DB migration
mix ecto.setup

# Start the server
mix phx.server