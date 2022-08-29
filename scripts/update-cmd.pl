#!/usr/bin/perl
use FindBin qw($Bin);
require "$Bin/json_pp.pm";
use Data::Dumper;
use strict;

sub create_state() {
	return {
		route => {},
		ipaddr => {},
	};
}

sub cmd($) {
	my $cmd = shift;
	print STDERR "command: $cmd\n";
	system($cmd);
}

sub fetch_active_data_linux($$) {
	my $ifname = shift;
	my $data = shift;

	open DATA, "(ip -4 r s dev $ifname; ip -6 r s dev $ifname) |";
	while (<DATA>) {
		chomp;
		s/^\s+//;
		my @data = split /\s+/, $_;
		next if $data[0] =~ /^fe80:/;
		next if $data[0] =~ /^ff..:/;
		$data[0] =~ /(:|\/)/ or do {
			$data[0] .= '/32';
		};
		$data->{route}->{$data[0]} = 'delete';
	}
	close DATA;

	open DATA, "ip a s dev $ifname |";
	while (<DATA>) {
		chomp;
		s/^\s+//;
		my @data = split /\s+/, $_;
		next unless $data[0] =~ /inet/;
		next if $data[1] =~ /^fe80:/;
		$data->{ipaddr}->{$data[1]} = 'delete';
	}
	close DATA;
}

sub fetch_active_data_darwin($$) {
	my $ifname = shift;
	my $data = shift;

	open DATA, "netstat -rn |";
	while (<DATA>) {
		chomp;
		s/^\s+//;
		my @data = split /\s+/, $_;
		next unless $data[3] eq $ifname;
		next if $data[0] =~ /^fe80:/;
		next if $data[0] =~ /^ff..:/;
		$data[0] =~ /(:|\/)/ or do {
			my $mask = 32;
			my @addr = split /\./, $data[0];
			while (@addr < 4) {
				push @addr, '0';
				$mask -= 8;
			}
			$data[0] = join(".", @addr)."/$mask";
		};
		$data->{route}->{$data[0]} = 'delete';
	}
	close DATA;

	open DATA, "ifconfig $ifname |";
	while (<DATA>) {
		chomp;
		s/^\s+//;
		my @data = split /\s+/, $_;
		next unless $data[0] =~ /inet/;
		next if $data[1] =~ /^fe80:/;
		$data->{ipaddr}->{$data[1]} = 'delete';
	}
	close DATA;
}

sub update_data($$$) {
	my $data = shift;
	my $delete = shift;
	my $add = shift;

	return unless $data->{"link-up"} eq 1;
	foreach my $val (@{$data->{ipaddr}}, @{$data->{ip6addr}}) {
		my $ip = $val->{ipaddr};
		my $mask = $val->{mask};

		if ($ip =~ /:/) {
			my $route = $ip;
			if (not($ip =~ /::/) and $mask eq 64) {
				$route =~ s/((\w+):(\w+):(\w+):(\w+)):.*/$1::/;
			} else {
				$route = "$ip/128";
			}
			push @{$data->{routes6}}, { target => "$route", "netmask" => $mask };
		} else {
			push @{$data->{routes}}, { target => "$ip", "netmask" => 32 };
		};
		if ($delete->{ipaddr}->{$ip}) {
			delete $delete->{ipaddr}->{$ip};
		} elsif ($delete->{ipaddr}->{"$ip/$mask"}) {
			delete $delete->{ipaddr}->{"$ip/$mask"};
		} else {
			$add->{ipaddr}->{"$ip/$mask"} = 'add';
		}
	}
	foreach my $val (@{$data->{routes}}, @{$data->{routes6}}) {
		my $ip = $val->{target}.'/'.$val->{netmask};

		if ($delete->{route}->{$ip}) {
			delete $delete->{route}->{$ip};
		} else {
			$add->{route}->{$ip} = 'add';
		}
	}
}

sub set_active_data_linux($$$) {
	my $ifname = shift;
	my $delete = shift;
	my $add = shift;

	(keys %{$add->{ipaddr}}, keys %{$add->{route}}) > 0 and cmd("ip l s dev $ifname up");

	foreach my $ip (keys %{$delete->{ipaddr}}) {
		cmd("ip a d $ip dev $ifname");
	}
	foreach my $route (keys %{$delete->{route}}) {
		cmd("ip r d $route dev $ifname");
	}

	foreach my $ip (keys %{$add->{ipaddr}}) {
		cmd("ip a a $ip dev $ifname");
	}
	foreach my $route (keys %{$add->{route}}) {
		cmd("ip r a $route dev $ifname");
	}
}

sub set_active_data_darwin($$$) {
	my $ifname = shift;
	my $delete = shift;
	my $add = shift;

	foreach my $ip (keys %{$delete->{ipaddr}}) {
		$ip =~ s/\/.*//;
		if ($ip =~ /:/) {
			cmd("ifconfig $ifname inet6 delete $ip");
		} else {
			cmd("ifconfig $ifname delete $ip");
		}
	}
	foreach my $route (keys %{$delete->{route}}) {
		if ($route =~ /:/)  {
			cmd("route delete -inet6 $route -iface $ifname");
		} else {
			cmd("route delete -inet $route -iface $ifname");
		}
	}
	foreach my $ip (keys %{$add->{ipaddr}}) {
		my @ip = split /\//, $ip;

		if ($ip[0] =~ /:/) {
			cmd("ifconfig $ifname inet6 add $ip[0] prefixlen $ip[1]");
		} else {
			cmd("ifconfig $ifname add $ip[0]/$ip[1] $ip[0]");
		}
	}
	foreach my $route (keys %{$add->{route}}) {
		if ($route =~ /:/)  {
			cmd("route add -inet6 $route -iface $ifname");
		} else {
			cmd("route add -inet $route -iface $ifname");
		}
	}
}

my $json = $ARGV[0];
my $platform = `uname`;
my $data = JSON::PP::decode_json($json) or die "Failed to decode JSON data\n";

my $delete = create_state();
my $add = create_state();

if ($platform =~ /Darwin/) {
	fetch_active_data_darwin($data->{ifname}, $delete);
} elsif ($platform =~ /Linux/) {
	fetch_active_data_linux($data->{ifname}, $delete);
} else {
	die "Unsupported platform $platform\n";
}

update_data($data, $delete, $add);

if ($platform =~ /Darwin/) {
	set_active_data_darwin($data->{ifname}, $delete, $add);
} elsif ($platform =~ /Linux/) {
	set_active_data_linux($data->{ifname}, $delete, $add);
}

# print Data::Dumper->Dump([$add, $delete], ["add", "delete"])."\n";
