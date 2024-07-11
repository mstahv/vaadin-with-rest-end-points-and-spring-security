package in.virit.sb.example.views;

import com.vaadin.flow.component.html.Emphasis;
import com.vaadin.flow.component.html.H1;
import com.vaadin.flow.component.login.LoginForm;
import com.vaadin.flow.component.orderedlayout.VerticalLayout;
import com.vaadin.flow.router.BeforeEnterEvent;
import com.vaadin.flow.router.BeforeEnterObserver;
import com.vaadin.flow.router.PageTitle;
import com.vaadin.flow.router.Route;
import com.vaadin.flow.server.auth.AnonymousAllowed;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

@Route("login") 
@PageTitle("Login | REST with Vaadin UI example")
@AnonymousAllowed
public class LoginView extends VerticalLayout implements BeforeEnterObserver {

	private static final Logger log = LoggerFactory.getLogger(LoginView.class);
	private final LoginForm login = new LoginForm();

	public LoginView(){
		setAlignItems(Alignment.CENTER);
		setJustifyContentMode(JustifyContentMode.CENTER);

		login.setAction("login");
		add(
				new H1("Vaadin + REST Example"),
				new Emphasis("Try user:password ;-)"),
				login
		);
	}

	@Override
	public void beforeEnter(BeforeEnterEvent beforeEnterEvent) {
		// inform the user about an authentication error
		if(beforeEnterEvent.getLocation()  
        .getQueryParameters()
        .getParameters()
        .containsKey("error")) {
            login.setError(true);
        }
	}
}