package globals

import (
	"sync"

	pb_accounts "github.com/PretendoNetwork/grpc-go/account"
	pb_friends "github.com/PretendoNetwork/grpc-go/friends"
	"github.com/PretendoNetwork/nex-go/v2"
	"github.com/PretendoNetwork/nex-go/v2/types"
	common_ticket_granting "github.com/PretendoNetwork/nex-protocols-common-go/v2/ticket-granting"
	"github.com/PretendoNetwork/plogger-go"
	"google.golang.org/grpc"
	"google.golang.org/grpc/metadata"
)

var Logger *plogger.Logger
var KerberosPassword = "password" // * Default password
var AuthenticationServer *nex.PRUDPServer
var AuthenticationEndpoint *nex.PRUDPEndPoint
var SecureServer *nex.PRUDPServer
var SecureEndpoint *nex.PRUDPEndPoint
var GRPCAccountClientConnection *grpc.ClientConn
var GRPCAccountClient pb_accounts.AccountClient
var GRPCAccountCommonMetadata metadata.MD
var GRPCFriendsClientConnection *grpc.ClientConn
var GRPCFriendsClient pb_friends.FriendsClient
var GRPCFriendsCommonMetadata metadata.MD
var CommonAuthProtocol *common_ticket_granting.CommonProtocol
var _ = types.NewString // prevent unused import

// SessionPasswords maps PID → session token set by customLoginEx.
// Used by AccountDetailsByPID so RequestTicket uses the session key
// rather than the real Pretendo password from gRPC.
var sessionPasswordsMu sync.RWMutex
var sessionPasswords = map[uint64]string{}

func SetSessionPassword(pid uint64, password string) {
	sessionPasswordsMu.Lock()
	sessionPasswords[pid] = password
	sessionPasswordsMu.Unlock()
}

func GetSessionPassword(pid uint64) (string, bool) {
	sessionPasswordsMu.RLock()
	p, ok := sessionPasswords[pid]
	sessionPasswordsMu.RUnlock()
	return p, ok
}
