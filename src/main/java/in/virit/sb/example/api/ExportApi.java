package in.virit.sb.example.api;

import in.virit.sb.example.Message;
import in.virit.sb.example.MessageService;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;

/**
 * Example of public API endpoint for exporting data.
 */
@RestController
@RequestMapping("/api/public")
public class ExportApi {

    private final MessageService messageService;

    public ExportApi(MessageService messageService) {
        this.messageService = messageService;
    }

    @GetMapping("export")
    public List<Message> exportMessages() {
        return messageService.getMessages();
    }
}
