# =============================================================================
# Multi-stage Dockerfile — country-service (Spring Boot 3.4.3 / Java 11)
# =============================================================================
#
# Security decisions:
#
# 1. Multi-stage build — the JDK, Maven cache, and source code never exist in
#    the final image. Only the compiled JAR is copied across. This eliminates
#    an entire class of supply-chain risk: build tools and source code cannot
#    be extracted from the production image.
#
# 2. Eclipse Temurin on Alpine — Eclipse Temurin is the Adoptium community
#    build of OpenJDK (no Oracle licensing concerns). Alpine Linux has a
#    minimal package set (~5 MB base), drastically reducing the attack surface
#    compared to debian-slim or ubuntu bases.
#
# 3. JRE runtime image, not JDK — the runtime stage uses the JRE variant.
#    The JDK includes javac, jmap, jstack, jconsole and other tooling that an
#    attacker could abuse post-compromise. The JRE omits all of these.
#
# 4. Explicit non-root user (UID 1001) — containers running as root (UID 0)
#    can escape to the host if the container runtime is misconfigured.
#    A dedicated non-root user limits the blast radius of any container escape.
#
# 5. Minimal COPY — only the compiled JAR is copied. No .git directory,
#    no config files with potential credentials, no test resources.
#
# 6. No ENV/ARG for secrets — secrets are injected at runtime via environment
#    variables, not baked into the image layer history.
# =============================================================================

# -----------------------------------------------------------------------------
# Stage 1: BUILD
# Uses the full JDK + Maven to compile and package the application.
# This stage is discarded after build — its contents never reach production.
# -----------------------------------------------------------------------------
FROM eclipse-temurin:11-jdk-alpine AS build

# Set a consistent working directory for the build
WORKDIR /build

# Copy dependency descriptors first to exploit Docker layer caching.
# Maven dependencies are only re-downloaded when pom.xml changes,
# not on every source code change.
COPY application/src/country-service-main/pom.xml .
COPY application/src/country-service-main/.mvn/ .mvn/
COPY application/src/country-service-main/mvnw .

# Make the Maven wrapper executable
RUN chmod +x mvnw

# Download dependencies in a separate layer (cached unless pom.xml changes)
RUN ./mvnw dependency:go-offline -B --no-transfer-progress

# Now copy source code and build
COPY application/src/country-service-main/src/ src/

# Package the application:
#   -B            = batch mode (no interactive prompts)
#   -DskipTests   = skip unit tests (tests run in a dedicated CI job)
#   --no-transfer-progress = cleaner CI logs
RUN ./mvnw package -B -DskipTests --no-transfer-progress

# -----------------------------------------------------------------------------
# Stage 2: RUNTIME
# Minimal JRE-only image. Contains only what is needed to run the JAR.
# -----------------------------------------------------------------------------
FROM eclipse-temurin:11-jre-alpine AS runtime

# Security: create a dedicated non-root system user and group.
# Explicit UID/GID (1001) ensures consistent identity across environments
# and avoids collision with any host user that might share a UID.
RUN addgroup -S -g 1001 appgroup && \
    adduser  -S -u 1001 -G appgroup -H -D appuser

# Application working directory — owned by non-root user
WORKDIR /app
RUN chown appuser:appgroup /app

# Copy ONLY the compiled JAR from the build stage.
# Nothing else (source, .git, config files, credentials) is included.
COPY --from=build --chown=appuser:appgroup \
     /build/target/country-service-0.0.1-SNAPSHOT.jar \
     app.jar

# Switch to non-root user for all subsequent commands and at runtime
USER appuser

# Document the port the application listens on (Spring Boot default).
# EXPOSE is documentation only — actual port mapping is in docker-compose.yml.
EXPOSE 8080

# Health check — Docker and Compose can restart unhealthy containers.
# Uses wget (available in Alpine) to hit the Spring Boot actuator endpoint.
HEALTHCHECK --interval=30s --timeout=10s --start-period=60s --retries=3 \
    CMD wget --no-verbose --tries=1 --spider http://localhost:8080/actuator/health \
    || exit 1

# Runtime entry point.
# JVM flags:
#   -XX:+UseContainerSupport   — respect cgroup CPU/memory limits (Java 11+)
#   -XX:MaxRAMPercentage=75.0  — use up to 75% of container memory for heap
#   -Djava.security.egd=...    — faster startup by using /dev/urandom for entropy
#   -Dspring.profiles.active   — overrideable via environment variable
ENTRYPOINT ["java", \
    "-XX:+UseContainerSupport", \
    "-XX:MaxRAMPercentage=75.0", \
    "-Djava.security.egd=file:/dev/./urandom", \
    "-jar", "app.jar"]
