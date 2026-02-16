FROM eclipse-temurin:17-jdk-jammy

WORKDIR /app

COPY target/timesheet-devops-1.0.jar app.jar

EXPOSE 8082

ENTRYPOINT ["java","-jar","app.jar"]
