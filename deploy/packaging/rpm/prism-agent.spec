Name: prism-agent
Version: %{_version}
Release: 1%{?dist}
Summary: Prism eBPF observability agent
License: Apache-2.0

%description
Prism eBPF observability agent.

%install
mkdir -p %{buildroot}/usr/bin
mkdir -p %{buildroot}/etc/prism
mkdir -p %{buildroot}/usr/share/doc/prism-agent
mkdir -p %{buildroot}/lib/systemd/system
install -m 0755 target/x86_64-unknown-linux-musl/release/prism-agent %{buildroot}/usr/bin/prism-agent
install -m 0644 config/example.yaml %{buildroot}/etc/prism/config.yaml
install -m 0644 config/example.yaml %{buildroot}/usr/share/doc/prism-agent/config.example.yaml
install -m 0644 deploy/systemd/prism-agent.service %{buildroot}/lib/systemd/system/prism-agent.service
install -m 0644 LICENSE %{buildroot}/usr/share/doc/prism-agent/LICENSE

%post
%systemd_post prism-agent.service
systemctl restart prism-agent.service >/dev/null 2>&1 || :

%preun
%systemd_preun prism-agent.service

%postun
%systemd_postun_with_restart prism-agent.service

%files
/usr/bin/prism-agent
%config(noreplace) /etc/prism/config.yaml
/lib/systemd/system/prism-agent.service
/usr/share/doc/prism-agent/LICENSE
/usr/share/doc/prism-agent/config.example.yaml
