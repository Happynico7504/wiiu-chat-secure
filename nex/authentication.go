package nex

import (
	"crypto/rand"
	"fmt"
	"os"
	"strconv"

	nex "github.com/PretendoNetwork/nex-go/v2"
	"github.com/PretendoNetwork/nex-go/v2/types"
	common_ticket_granting "github.com/PretendoNetwork/nex-protocols-common-go/v2/ticket-granting"
	ticket_granting "github.com/PretendoNetwork/nex-protocols-go/v2/ticket-granting"
	tg_types "github.com/PretendoNetwork/nex-protocols-go/v2/ticket-granting/types"
	"github.com/PretendoNetwork/wiiu-chat/database"
	"github.com/PretendoNetwork/wiiu-chat/globals"

	// Ensure NintendoLoginData and friends are registered in AnyObjectHolder.
	_ "github.com/PretendoNetwork/nex-protocols-go/v2"
)

var serverBuildString string

func StartAuthenticationServer() {
	serverBuildString = "branch:ngs_2_30 build:2_22_11148_30_2"

	globals.AuthenticationServer = nex.NewPRUDPServer()

	globals.AuthenticationEndpoint = nex.NewPRUDPEndPoint(1)
	globals.AuthenticationEndpoint.ServerAccount = globals.AuthenticationServerAccount
	globals.AuthenticationEndpoint.AccountDetailsByPID = globals.AccountDetailsByPID
	globals.AuthenticationEndpoint.AccountDetailsByUsername = globals.AccountDetailsByUsername
	globals.AuthenticationServer.BindPRUDPEndPoint(globals.AuthenticationEndpoint)
	globals.AuthenticationServer.ByteStreamSettings.UseStructureHeader = false

	// Technically this title is 3.4.2; however, it uses older-style structures and is therefore defined here as 3.3.2
	globals.AuthenticationServer.LibraryVersions.SetDefault(nex.NewLibraryVersion(3, 3, 2))
	globals.AuthenticationServer.AccessKey = "e7a47214"

	globals.AuthenticationEndpoint.OnData(func(packet nex.PacketInterface) {
		request := packet.RMCMessage()

		fmt.Println("=== WUC - Auth ===")
		fmt.Printf("Protocol ID: %d\n", request.ProtocolID)
		fmt.Printf("Method ID: %d\n", request.MethodID)
		fmt.Println("==================")
	})

	registerCommonAuthenticationServerProtocols()

	// Register ONE protocol for all TicketGranting methods.
	// NewCommonProtocol sets Login and RequestTicket via the common library.
	// Copy metadata from CommonAuthProtocol (set by registerCommonAuthenticationServerProtocols)
	// so RequestTicket has the correct SecureStationURL and SecureServerAccount.
	// LoginEx is then overridden with our custom handler that uses session tokens.
	ticketGrantingProto := ticket_granting.NewProtocol()
	commonProto := common_ticket_granting.NewCommonProtocol(ticketGrantingProto)
	commonProto.SecureStationURL = globals.CommonAuthProtocol.SecureStationURL
	commonProto.BuildName = globals.CommonAuthProtocol.BuildName
	commonProto.SecureServerAccount = globals.CommonAuthProtocol.SecureServerAccount
	globals.CommonAuthProtocol = commonProto
	globals.AuthenticationEndpoint.RegisterServiceProtocol(ticketGrantingProto)
	ticketGrantingProto.SetHandlerLoginEx(customLoginEx)

	port, _ := strconv.Atoi(os.Getenv("PN_WUC_AUTHENTICATION_SERVER_PORT"))

	globals.AuthenticationServer.Listen(port)
}

func customLoginEx(
	err error,
	packet nex.PacketInterface,
	callID uint32,
	strUserName types.String,
	oExtraData types.DataHolder,
) (*nex.RMCMessage, *nex.Error) {
	if err != nil {
		return nil, nex.NewError(nex.ResultCodes.Core.InvalidArgument, err.Error())
	}

	var sessionToken string
	switch v := oExtraData.Object.(type) {
	case tg_types.NintendoLoginData:
		sessionToken = string(v.Token)
	case tg_types.AuthenticationInfo:
		sessionToken = string(v.Token)
	default:
		fmt.Printf("LoginEx: unexpected oExtraData type %T\n", oExtraData.Object)
		return nil, nex.NewError(nex.ResultCodes.Core.InvalidArgument, "unsupported oExtraData type")
	}

	if !database.ValidateSessionToken(sessionToken) {
		fmt.Printf("LoginEx: token not in nex_sessions or expired (token=%q)\n", sessionToken)
		return nil, nex.NewError(nex.ResultCodes.Authentication.ValidationFailed, "invalid or expired session token")
	}

	pidInt, parseErr := strconv.ParseUint(string(strUserName), 10, 64)
	if parseErr != nil {
		return nil, nex.NewError(nex.ResultCodes.RendezVous.InvalidUsername, "username is not a PID")
	}
	pid := types.NewPID(pidInt)

	// Cache session token so AccountDetailsByPID returns it for RequestTicket.
	globals.SetSessionPassword(pidInt, sessionToken)

	// Store PID so the HTTP proxy can return it for future nex_token requests from this IP.
	database.SetSessionPID(sessionToken, uint32(pidInt))

	// Upsert into nex_accounts so PasswordFromPID works for the secure server.
	database.Postgres.Exec(`
		INSERT INTO nex_accounts (pid, username, nex_password)
		VALUES ($1, $2, $3)
		ON CONFLICT (pid) DO UPDATE SET nex_password = EXCLUDED.nex_password
	`, uint32(pidInt), string(strUserName), sessionToken)

	connection := packet.Sender().(*nex.PRUDPConnection)
	endpoint := connection.Endpoint().(*nex.PRUDPEndPoint)

	// Generate Kerberos ticket: source=(PID, sessionToken), target=secure server account.
	sourceKey := nex.DeriveKerberosKey(pid, []byte(sessionToken))
	targetKey := nex.DeriveKerberosKey(
		globals.SecureServerAccount.PID,
		[]byte(globals.SecureServerAccount.Password),
	)

	sessionKey := make([]byte, 32)
	if _, randErr := rand.Read(sessionKey); randErr != nil {
		return nil, nex.NewError(nex.ResultCodes.Authentication.Unknown, "failed to generate session key")
	}

	ticketInternal := nex.NewKerberosTicketInternalData(endpoint.Server)
	ticketInternal.Issued = types.NewDateTime(0).Now()
	ticketInternal.SourcePID = pid
	ticketInternal.SessionKey = sessionKey

	encInternal, encErr := ticketInternal.Encrypt(
		targetKey,
		nex.NewByteStreamOut(endpoint.LibraryVersions(), endpoint.ByteStreamSettings()),
	)
	if encErr != nil {
		return nil, nex.NewError(nex.ResultCodes.Authentication.Unknown, "failed to encrypt ticket internal data")
	}

	ticket := nex.NewKerberosTicket()
	ticket.SessionKey = sessionKey
	ticket.TargetPID = globals.SecureServerAccount.PID
	ticket.InternalData = types.NewBuffer(encInternal)

	encTicket, encErr := ticket.Encrypt(
		sourceKey,
		nex.NewByteStreamOut(endpoint.LibraryVersions(), endpoint.ByteStreamSettings()),
	)
	if encErr != nil {
		return nil, nex.NewError(nex.ResultCodes.Authentication.Unknown, "failed to encrypt ticket")
	}

	proto := globals.CommonAuthProtocol
	pConnectionData := types.NewRVConnectionData()
	pConnectionData.StationURL = proto.SecureStationURL
	pConnectionData.SpecialProtocols = proto.SpecialProtocols
	pConnectionData.StationURLSpecialProtocols = proto.StationURLSpecialProtocols
	pConnectionData.Time = types.NewDateTime(0).Now()
	if endpoint.LibraryVersions().Main.GreaterOrEqual("v3.5.0") {
		pConnectionData.StructureVersion = 1
	}

	rmcStream := nex.NewByteStreamOut(endpoint.LibraryVersions(), endpoint.ByteStreamSettings())
	types.NewQResultSuccess(nex.ResultCodes.Core.Unknown).WriteTo(rmcStream)
	pid.WriteTo(rmcStream)
	types.NewBuffer(encTicket).WriteTo(rmcStream)
	pConnectionData.WriteTo(rmcStream)
	proto.BuildName.Copy().(types.String).WriteTo(rmcStream)

	rmcResponse := nex.NewRMCSuccess(endpoint, rmcStream.Bytes())
	rmcResponse.ProtocolID = ticket_granting.ProtocolID
	rmcResponse.MethodID = ticket_granting.MethodLoginEx
	rmcResponse.CallID = callID

	fmt.Printf("LoginEx: PID=%d authenticated via session token\n", pidInt)
	return rmcResponse, nil
}
