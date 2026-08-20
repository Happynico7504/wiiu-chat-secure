package database

import (
	"github.com/PretendoNetwork/nex-go/v2/types"
	"github.com/PretendoNetwork/wiiu-chat/globals"
)

func EndCall(caller types.PID) {
	// If the call was still ringing when cancelled, record it as a missed call for the target.
	_, err := Postgres.Exec(`
		INSERT INTO missed_calls (caller_pid, target_pid)
		SELECT caller_pid, target_pid FROM ongoingcalls
		WHERE caller_pid = $1 AND ringing = true;`, caller)
	if err != nil {
		globals.Logger.Critical(err.Error())
	}

	_, err = Postgres.Exec(`DELETE FROM ongoingcalls WHERE caller_pid = $1;`, caller)
	if err != nil {
		globals.Logger.Critical(err.Error())
	}
}
