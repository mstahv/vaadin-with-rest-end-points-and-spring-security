package in.virit.sb.example.api;

import in.virit.sb.example.Message;
import in.virit.sb.example.MessageService;
import org.springframework.http.MediaType;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/private")
public class ImportApi {

    private final MessageService messageService;

    public ImportApi(MessageService messageService) {
        this.messageService = messageService;
    }

    @PostMapping("import")
    public String importData(@RequestBody Message msg) {
        messageService.addMessage(msg);
        return "Message added\n";
    }

}
