FROM gcr.io/distroless/cc-debian12


WORKDIR /app

COPY silo /usr/local/bin/silo

# Default config location
COPY silo.yaml /app/silo.yaml

ENV SILO_CONFIG=/app/silo.yaml
ENV RUST_LOG=info

EXPOSE 8443 6192 50051

ENTRYPOINT ["/usr/local/bin/silo"]
