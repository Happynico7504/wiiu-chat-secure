package database

import (
	"github.com/PretendoNetwork/nex-go/v2/types"
	"github.com/PretendoNetwork/wiiu-chat/globals"
)

type MissedCall struct {
	CallerPID types.PID
}

func GetMissedCalls(target types.PID) []MissedCall {
	rows, err := Postgres.Query(`SELECT caller_pid FROM missed_calls WHERE target_pid = $1 ORDER BY called_at ASC;`, target)
	if err != nil {
		globals.Logger.Critical(err.Error())
		return nil
	}
	defer rows.Close()

	var calls []MissedCall
	for rows.Next() {
		var callerPID types.PID
		if err := rows.Scan(&callerPID); err != nil {
			globals.Logger.Warning(err.Error())
			continue
		}
		calls = append(calls, MissedCall{CallerPID: callerPID})
	}
	return calls
}

func ClearMissedCalls(target types.PID) {
	_, err := Postgres.Exec(`DELETE FROM missed_calls WHERE target_pid = $1;`, target)
	if err != nil {
		globals.Logger.Critical(err.Error())
	}
}
