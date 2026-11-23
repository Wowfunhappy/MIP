#!/bin/sh
# Uninstalls SIMBL (Wowfunhappy's SIMBL package), including its plugins and settings.

[ "$(id -u)" = 0 ] || exec sudo "$0" "$@"
USER_HOME=$(eval echo "~$SUDO_USER")

# Stop the agent in the logged-in user's session.
sudo -u "$SUDO_USER" launchctl unload /Library/LaunchAgents/net.culater.SIMBL.Agent.plist

rm -f  /Library/LaunchAgents/net.culater.SIMBL.Agent.plist
rm -rf /System/Library/ScriptingAdditions/SIMBL.osax
rm -rf "/Library/Application Support/SIMBL"
rm -rf "$USER_HOME/Library/Application Support/SIMBL"
rm -f  "$USER_HOME/Library/Preferences/net.culater.SIMBL.plist"
rm -f  "$USER_HOME/Library/Preferences/org.w0lf.SIMBLAgent.plist"

pkgutil --forget com.Wowfunhappy.MavSIMBL
