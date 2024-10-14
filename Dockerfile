FROM openjdk:17-jdk-slim

COPY build/lib/gateway-service-0.0.1-SNAPSHOT.jar /gateway-service.jar

ENTRYPOINT ["java", "-jar", "/gateway-service.jar"]

EXPOSE 8000
