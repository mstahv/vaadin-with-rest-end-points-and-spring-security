package in.virit.sb.example;

import org.springframework.stereotype.Service;

import java.util.ArrayList;
import java.util.List;

@Service
public class MessageService {
    private List<Message> msgs = new ArrayList<>();

    public List<Message> getMessages() {
        return new ArrayList<>(msgs);
    }

    public void addMessage(Message msg) {
        msgs.add(msg);
    }

}
