package Net::EPP::MITMProxy;
# ABSTRACT: A generic EPP proxy server framework.
use IO::Socket::SSL;
use Mozilla::CA;
use Net::EPP::Protocol;
use Socket6;
use Socket;
use SUPER;
use XML::LibXML;
use base qw(Net::Server::PreFork);
use feature qw(state);
use vars qw($OPT_KEY $HELLO);
use bytes;
use strict;

my $OPT_KEY = __PACKAGE__.'::opts';
my $HELLO   = '<epp xmlns="urn:ietf:params:xml:ns:epp-1.0"><hello/></epp>';

=pod

=head1 SYNOPSIS

    package My::Proxy::Server;
    use base qw(Net::EPP::MITMProxy);

    sub rewrite_command {
        my ($self, $xml) = @_;

        # do something to $xml here

        return $xml;
    }

    #
    # note: $command_xml contains the original unmodified command from the
    # client, not the rewritten command
    #
    sub rewrite_response {
        my ($self, $response_xml, $command_xml) = @_;

        # do something to $response_xml here

        return $response_xml;
    }

    __PACKAGE__->new->run(%OPTIONS);

=head1 INTRODUCTION

This module implements an EPP proxy server that acts as a machine-in-the-middle
between client and server, and allows EPP command and response frames to be
modified in-flight.

=head1 OPTIONS

This module inherits from L<Net::Server::Prefork> and so supports all of that
module's options, in addition to the following:

=over

=item * C<remote_server> - the remote EPP server name.

=item * C<remote_port> - the remote EPP server port (default 700).

=item * C<remote_key> - (OPTIONAL) the private key to use to connect to the
remote server.

=item * C<remote_cert> - (OPTIONAL) the certificate to use to connect to the
remote server.

=back

Note that a limitation of the current approach is that it is not possible to
connect to the remote server using a client certificate determined by the
identity of the client.

=cut

sub run {
    my ($self, %args) = @_;

    $self->{$OPT_KEY} = {
        remote_server   => delete($args{remote_server}),
        remote_port     => delete($args{remote_port}) || 700,
        remote_key      => delete($args{remote_key}),
        remote_cert     => delete($args{remote_cert}),
    };

    super;
}

sub process_request {
    my ($self, $client) = @_;

    my $server = $self->connect_to_remote_server;
    return unless ($server);

    my $frame = $self->get_frame($server);
    if (!$frame) {
        $self->log(0, 'error getting <greeting> from remote server');
        return;
    }

    $self->send_frame($client, $self->rewrite_response($frame, $HELLO, $client));

    while (1) {
        my $command = $self->get_frame($client);

        if (!$command) {
            $self->log(0, 'error getting command frame from client');
            last;
        }

        $self->send_frame($server, $self->rewrite_command($command, $client));

        my $response = $self->get_frame($server);

        if (!$response) {
            $self->log(0, 'error getting response frame from remote server');
            last;
        }

        $self->send_frame($client, $self->rewrite_response($response, $command, $client));
    }

    return;
}

sub connect_to_remote_server {
    my $self = shift;

    my %args = (
        PeerHost        => $self->{$OPT_KEY}->{remote_server},
        PeerPort        => $self->{$OPT_KEY}->{remote_port},
        SSL_verify_mode => SSL_VERIFY_PEER,
        SSL_ca_file     => Mozilla::CA::SSL_ca_file(),
    );

    if ($self->{$OPT_KEY}->{remote_key} && $self->{$OPT_KEY}->{remote_cert}) {
        $args{SSL_key_file}     = $self->{$OPT_KEY}->{remote_key};
        $args{SSL_cert_file}    = $self->{$OPT_KEY}->{remote_cert};
    }

    my $server = IO::Socket::SSL->new(%args);

    if (!$server) {
        $self->log(0, sprintf(
            'connection to [%s]:%u failed (error=%s, SSL error=%s)',
            $self->{$OPT_KEY}->{remote_server},
            $self->{$OPT_KEY}->{remote_port},
            $!,
            $SSL_ERROR
        ));
        return;
    }

    return $server;
}

sub get_frame {
    my ($self, $socket) = @_;

    return Net::EPP::Protocol->get_frame($socket);
}

sub send_frame {
    my $self = shift;

    return Net::EPP::Protocol->send_frame(@_);
}

=pod

=head1 REWRITING COMMANDS

To rewrite EPP commands before they're sent to the remote server, you must
implement your own C<rewrite_command()> method.

    sub rewrite_command {
        my ($self, $xml, $client) = @_;

        # do something to $xml here

        return $xml;
    }

The C<rewrite_command()> method is passed a scalar containing the XML received
from the client, and should return the modified command XML.

=cut

sub rewrite_command {
    my ($self, $command_xml) = @_;

    return $command_xml;
}

=pod

=head1 REWRITING RESPONSES

To rewrite EPP commands before they're sent to the remote server, you must
implement your own C<rewrite_response()> method.

    sub rewrite_response {
        my ($self, $response_xml, $command_xml, $client) = @_;

        # do something to $response_xml here

        return $response_xml;
    }

The C<rewrite_response()> method is passed both the original command XML from the
client, and the response XML from the remote server, and should return the
modified response XML.

=cut

sub rewrite_response {
    my ($self, $response_xml, $command_xml) = @_;

    return $response_xml;
}

1;
