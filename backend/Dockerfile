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
# Spring Boot repackages a single executable jar in target/
COPY --from=build /app/target/*.jar app.jar
EXPOSE 8080
# Profile + all secrets/DB come from environment (see docker-compose.yml).
ENV JAVA_OPTS="-XX:MaxRAMPercentage=75"
ENTRYPOINT ["sh","-c","java $JAVA_OPTS -jar app.jar"]
