package nex_matchmake_extension

import (
	nex "github.com/PretendoNetwork/nex-go/v2"
	"github.com/PretendoNetwork/nex-go/v2/types"
	"github.com/PretendoNetwork/wiiu-chat/database"
	"github.com/PretendoNetwork/wiiu-chat/globals"

	matchmake_extension "github.com/PretendoNetwork/nex-protocols-go/v2/matchmake-extension"
	notifications_constants "github.com/PretendoNetwork/nex-protocols-go/v2/notifications/constants"
	notifications_types "github.com/PretendoNetwork/nex-protocols-go/v2/notifications/types"
)

func GetFriendNotificationData(err error, packet nex.PacketInterface, callID uint32, uiType notifications_constants.NotificationCategorySigned) (*nex.RMCMessage, *nex.Error) {
	dataList := types.NewList[notifications_types.NotificationEvent]()
	myPID := packet.Sender().PID()

	// Active incoming call (still ringing).
	caller, target, ringing := database.GetCallInfoByTarget(myPID)
	if caller != 0 && target == myPID && ringing {
		notificationType := notifications_constants.NotificationCategoryGameNotification1.Build()

		notification := notifications_types.NewNotificationEvent()
		notification.PIDSource = caller
		notification.Type = notificationType
		notification.Param1 = types.UInt64(uint64(caller))
		notification.Param2 = types.UInt64(uint64(target))
		notification.StrParam = "Invite Request"

		dataList = append(dataList, notification)
	}

	rmcResponseStream := nex.NewByteStreamOut(globals.SecureServer.LibraryVersions, globals.SecureServer.ByteStreamSettings)
	dataList.WriteTo(rmcResponseStream)

	rmcResponse := nex.NewRMCSuccess(globals.SecureEndpoint, rmcResponseStream.Bytes())
	rmcResponse.ProtocolID = matchmake_extension.ProtocolID
	rmcResponse.CallID = callID
	rmcResponse.MethodID = matchmake_extension.MethodGetFriendNotificationData

	return rmcResponse, nil
}
