/*
 * Copyright 2024 Viritin.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package in.virit.sb.example.views;

import com.vaadin.flow.component.UI;
import com.vaadin.flow.component.button.Button;
import com.vaadin.flow.component.html.H1;
import com.vaadin.flow.component.orderedlayout.VerticalLayout;
import com.vaadin.flow.component.textfield.TextField;
import com.vaadin.flow.router.Route;
import com.vaadin.flow.spring.security.AuthenticationContext;
import in.virit.sb.example.Message;
import in.virit.sb.example.MessageService;
import jakarta.annotation.security.PermitAll;
import org.springframework.security.core.userdetails.UserDetails;
import org.vaadin.firitin.components.RichText;
import org.vaadin.firitin.components.grid.VGrid;
import org.vaadin.firitin.components.orderedlayout.VHorizontalLayout;

@Route
// Request authenticated user
@PermitAll
public class MainView extends VerticalLayout {
    
    public MainView(AuthenticationContext auth, MessageService messageService) {
        add(new H1("It works! You are logged in as " + auth.getAuthenticatedUser(UserDetails.class).get().getUsername()));

        add(new RichText().withMarkDown("""
        This is the Vaadin part of this example, nothing special here. You can also access the same data using REST API. 
        You can try with CLI using following cURL examples. Accessing (without need for authentication):
        
            curl http://localhost:8080/api/public/export

        Inserting new messages (with basic httpt auth authentication):
        
            curl -H "Content-Type: application/json" \\ 
                -u user:password --request POST  --data '{"user" : "Masa", "message" : "Olink eka?!"}' \\ 
                http://localhost:8080/api/private/import
                
        """));

        var grid = new VGrid<Message>(Message.class)
                .withHeight("300px");
        var userField = new TextField("User");
        var msgField = new TextField("Message");
        add(new VHorizontalLayout(
                userField,
                msgField,
                new Button("Send", e -> {
                    messageService.addMessage(new Message(userField.getValue(), msgField.getValue()));
                    grid.setItems(messageService.getMessages());
                }),
                new Button("Refresh messages manually", e -> grid.setItems(messageService.getMessages())),
                new Button("Logout", e -> { auth.logout(); UI.getCurrent().navigate("");})
        ).withAlignItems(Alignment.BASELINE));

        add(grid);
        grid.setItems(messageService.getMessages());

    }
    
}
