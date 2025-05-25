# Multi-stage build for optimized image size
FROM maven:3.9.8-eclipse-temurin-21 AS build

# Set working directory
WORKDIR /app

# Copy pom.xml first to leverage Docker layer caching
COPY pom.xml .

# Download dependencies (this layer will be cached if pom.xml doesn't change)
RUN mvn dependency:go-offline -B

# Copy source code
COPY src ./src

# Build the application
RUN mvn clean package -DskipTests

# Runtime stage
FROM eclipse-temurin:21-jre-jammy

# Set working directory
WORKDIR /app

# Create a non-root user for security
RUN groupadd -r payroll && useradd -r -g payroll payroll

# Copy the JAR from build stage
COPY --from=build /app/target/payroll-*.jar app.jar

# Change ownership to payroll user
RUN chown payroll:payroll app.jar

# Switch to non-root user
USER payroll

# Expose the port your app runs on
EXPOSE 8080

# Set JVM options for containerized environment
ENV JAVA_OPTS="-Xmx512m -Xms256m -Djava.security.egd=file:/dev/./urandom"

# Run the application
ENTRYPOINT ["sh", "-c", "java $JAVA_OPTS -jar app.jar"]