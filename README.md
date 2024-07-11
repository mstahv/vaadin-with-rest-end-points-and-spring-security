# An example project of a Spring Boot app providing both REST endpoints and a Vaadin UI

The example has default Vaadin Spring Security setup, but configured to cope with
two REST endpoints. One with public read access and one with secured access to post
messages. The Vaadin side is also secured, and contains further examples how to 
play with the demo.

Import the project to your IDE, run the main class `DevModeDemoApplication` and open
http://localhost:8080 in your browser.

## Notes

The app uses a [PoC of proper production builds](https://vaadin.com/forum/t/try-my-new-project-stubs-for-better-dx-cloud-compatibility-and-cleaner-pom-xml/166655), 
but it doesn't affect the actual demo of REST endpoints next to Vaadin UI and how to configure their security settings.

Start the project from the DevModeDemoApplication class on the test side, or with CLI
command `mvn spring-boot:test-run`. Otherwise the app is just normal Vaadin + Spring Boot app.

