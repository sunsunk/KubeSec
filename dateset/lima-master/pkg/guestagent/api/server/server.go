package server

import (
	"context"
	"net"

	"github.com/lima-vm/lima/pkg/guestagent"
	"github.com/lima-vm/lima/pkg/guestagent/api"
	"google.golang.org/grpc"
	"google.golang.org/protobuf/types/known/emptypb"
)

func StartServer(lis net.Listener, guest *GuestServer) error {
	server := grpc.NewServer()
	api.RegisterGuestServiceServer(server, guest)
	return server.Serve(lis)
}

type GuestServer struct {
	api.UnimplementedGuestServiceServer
	Agent guestagent.Agent
}

func (s GuestServer) GetInfo(ctx context.Context, _ *emptypb.Empty) (*api.Info, error) {
	return s.Agent.Info(ctx)
}

func (s GuestServer) GetEvents(_ *emptypb.Empty, stream api.GuestService_GetEventsServer) error {
	responses := make(chan *api.Event)
	go s.Agent.Events(stream.Context(), responses)
	for response := range responses {
		err := stream.Send(response)
		if err != nil {
			return err
		}
	}
	return nil
}

func (s GuestServer) PostInotify(server api.GuestService_PostInotifyServer) error {
	for {
		recv, err := server.Recv()
		if err != nil {
			return err
		}
		s.Agent.HandleInotify(recv)
	}
}
