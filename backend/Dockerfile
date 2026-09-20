# ---- build stage: compile the Spring Boot jar with Maven (Java 17) ----
FROM maven:3.9-eclipse-temurin-17 AS build
WORKDIR /app
# Cache dependencies first (only re-runs when pom.xml changes)
COPY pom.xml .
RUN mvn -q -e -B dependency:go-offline
# Build
COPY src ./src
RUN mvn -q -e -B -DskipTests clean package

# ---- runtime stage: slim JRE running the fat jar ----
FROM eclipse-temurin:17-jre
WORKDIR /app
# pcap4j (the PCAP-upload analysis) loads the native libpcap via JNA and fails
# with UnsatisfiedLinkError on the slim JRE, which ships no libpcap. Install the
# runtime lib, refresh the linker cache, and add the unversioned "libpcap.so"
# soname JNA looks up as "pcap" (the package only ships the versioned file).
RUN apt-get update \
 && apt-get install -y --no-install-recommends libpcap0.8 \
 && ldconfig \
 && ln -sf "$(ls /usr/lib/*/libpcap.so.* | head -n1)" /usr/lib/libpcap.so \
 && rm -rf /var/lib/apt/lists/*
# Spring Boot repackages a single executable jar in target/
COPY --from=build /app/target/*.jar app.jar
EXPOSE 8080
# Profile + all secrets/DB come from environment (see docker-compose.yml).
ENV JAVA_OPTS="-XX:MaxRAMPercentage=75"
ENTRYPOINT ["sh","-c","java $JAVA_OPTS -jar app.jar"]
