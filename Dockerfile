# ============================================================
# Multi-stage Dockerfile: Build HMDM + 2FA from source
# ============================================================
# Usage:
#   git clone https://github.com/novarpolizmir-ship-it/MDM-PANEL.git
#   cd MDM-PANEL
#   docker build -t hmdm-2fa:local .
# ============================================================

# Stage 1: Maven build
FROM maven:3.9-eclipse-temurin-11 AS builder

# Git is needed for bower
RUN apt-get update && apt-get install -y git && rm -rf /var/lib/apt/lists/*

WORKDIR /build

# Copy the full project
COPY . .

# Allow bower to run as root
RUN echo '{"allow_root": true}' > /build/server/webtarget/.bowerrc

# Build the WAR (skip tests)
RUN mvn clean package -DskipTests -Dproject.build.sourceEncoding=UTF-8

# Verify WAR was created
RUN ls -la /build/server/target/launcher.war

# ============================================================
# Stage 2: Overlay WAR on official HMDM image
FROM headwindmdm/hmdm:latest

# Remove old webapp (will be re-extracted from new WAR)
RUN rm -rf /usr/local/tomcat/webapps/ROOT /usr/local/tomcat/webapps/ROOT.war

# Copy the new WAR with 2FA support
COPY --from=builder /build/server/target/launcher.war /usr/local/tomcat/webapps/ROOT.war
