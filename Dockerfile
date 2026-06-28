FROM gcr.io/distroless/static-debian12

COPY target/x86_64-unknown-linux-musl/release/prism-agent /usr/bin/prism-agent
COPY target/bpfel-unknown-none/release/prism-ebpf /usr/lib/prism/prism-ebpf
COPY config/example.yaml /etc/prism/config.yaml
COPY LICENSE /usr/share/doc/prism-agent/LICENSE

EXPOSE 9090
USER 0:0
ENTRYPOINT ["/usr/bin/prism-agent"]
CMD ["--config", "/etc/prism/config.yaml"]
