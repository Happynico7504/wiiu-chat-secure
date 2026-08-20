package nex_matchmake_extension

import (
	"github.com/PretendoNetwork/nex-go/v2"
	"github.com/PretendoNetwork/nex-go/v2/types"
	"github.com/PretendoNetwork/wiiu-chat/database"
	"github.com/PretendoNetwork/wiiu-chat/globals"
	"github.com/PretendoNetwork/wiiu-chat/grpc"
	nex_notifications "github.com/PretendoNetwork/wiiu-chat/nex/notifications"

	matchmake_extension "github.com/PretendoNetwork/nex-protocols-go/v2/matchmake-extension"
	notifications_constants "github.com/PretendoNetwork/nex-protocols-go/v2/notifications/constants"
)

func UpdateNotificationData(err error, packet nex.PacketInterface, callID uint32, uiType notifications_constants.NotificationCategory, uiParam1 types.UInt64, uiParam2 types.UInt64, strParam types.String) (*nex.RMCMessage, *nex.Error) {
	globals.Logger.Infof("uiType: %d, uiParam1: %d, uiParam2: %d, strParam: %s\r\n", uiType, uiParam1, uiParam2, strParam)
	recipientClient := globals.SecureEndpoint.FindConnectionByPID(uint64(uiParam2))

	if uiType == notifications_constants.NotificationCategoryGameNotification1 {
		notificationType := types.UInt32(notifications_constants.NotificationCategoryGameNotification1.Build())
		target := types.NewPID(uint64(uiParam2))
		database.NewCall(packet.Sender().PID(), target)

		if recipientClient != nil && recipientClient.StationURLs != nil {
			nex_notifications.ProcessNotificationEvent(callID, packet, notificationType, types.UInt32(uiParam1), types.UInt32(uiParam2), strParam)
		} else {
			grpc.SendFriendsNotification(packet.Sender().PID(), types.NewPID(uint64(uiParam2)), true)
		}
	}

	if uiType == notifications_constants.NotificationCategoryGameNotification2 {
		notificationType := types.UInt32(notifications_constants.NotificationCategoryGameNotification2.Build())
		caller := types.NewPID(uint64(uiParam1))

		database.EndCall(caller)

		if recipientClient != nil && recipientClient.StationURLs != nil {
			nex_notifications.ProcessNotificationEvent(callID, packet, notificationType, types.UInt32(uiParam1), types.UInt32(uiParam2), strParam)
		} else {
			grpc.SendFriendsNotification(packet.Sender().PID(), types.NewPID(uint64(uiParam2)), false)
		}
	}

	rmcResponse := nex.NewRMCSuccess(globals.SecureEndpoint, nil)
	rmcResponse.ProtocolID = matchmake_extension.ProtocolID
	rmcResponse.CallID = callID
	rmcResponse.MethodID = matchmake_extension.MethodUpdateNotificationData

	return rmcResponse, nil
}
