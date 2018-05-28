package burp;

import javax.swing.*;
import java.awt.*;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.io.File;
import java.io.IOException;
import java.io.PrintWriter;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.regex.Pattern;

public class BurpExtender implements IBurpExtender, ITab, IHttpListener {
    private static IBurpExtenderCallbacks callbacks;
    private static IExtensionHelpers helpers;
    private static PrintWriter stderr;
    public static JPanel mainPanel;
    public static JPanel fileSettingsPanel;
    public static int numFiles;
    public static ArrayList<FileSettings> replacements;

    @Override
    public void registerExtenderCallbacks(IBurpExtenderCallbacks _callbacks) {
        numFiles = 0;
        callbacks = _callbacks;
        helpers = callbacks.getHelpers();
        stderr = new PrintWriter(callbacks.getStderr(), true);
        replacements = new ArrayList<FileSettings>();

        callbacks.setExtensionName("File Replacer");

        this.setupUI();
        callbacks.addSuiteTab(this);
        callbacks.registerHttpListener(this);
    }

    @Override
    public String getTabCaption() {
        return "File Replacer";
    }

    private void setupUI() {
        mainPanel = new JPanel();
        mainPanel.setLayout(new GridBagLayout());

        GridBagConstraints c = new GridBagConstraints();
        c.anchor = GridBagConstraints.NORTHWEST;
        c.fill = GridBagConstraints.NONE;
        c.weightx = 1.0;
        c.gridx = 0;
        c.gridy = 0;

        JButton addButton = new JButton();
        addButton.setText("Add File");
        addButton.setAlignmentX(Component.LEFT_ALIGNMENT);
        addButton.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent actionEvent) {
                BurpExtender.addFile("", "");
                BurpExtender.mainPanel.revalidate();
                BurpExtender.mainPanel.repaint();
            }
        });
        mainPanel.add(addButton, c);

        c.gridy = 1;
        c.weighty = 1;
        c.fill = GridBagConstraints.HORIZONTAL;
        fileSettingsPanel = new JPanel();
        fileSettingsPanel.setLayout(new BoxLayout(fileSettingsPanel, BoxLayout.Y_AXIS));

        JScrollPane scrollPane = new JScrollPane(fileSettingsPanel);
        // Welcome to Java...
        scrollPane.setMinimumSize(new Dimension(Integer.MAX_VALUE, Integer.MAX_VALUE));
        mainPanel.add(scrollPane, c);

        callbacks.customizeUiComponent(mainPanel);
    }

    private static void addFile(String filename, String regex) {
        numFiles++;
        GridBagConstraints c = new GridBagConstraints();
        c.anchor = GridBagConstraints.NORTHWEST;
        c.fill = GridBagConstraints.HORIZONTAL;
        c.weightx = 1;
        c.gridx = 0;
        c.gridy = numFiles;

        File f = Paths.get(filename).toFile();
        Pattern p = Pattern.compile(regex);
        FileSettings fs = new FileSettings(f, p);
        fileSettingsPanel.add(fs.panel, c);
        replacements.add(fs);
    }

    static void removeFile(JPanel filePanel) {
        fileSettingsPanel.remove(filePanel);
        fileSettingsPanel.revalidate();
        fileSettingsPanel.repaint();
        numFiles--;
    }

    @Override
    public Component getUiComponent() {
        System.out.println(mainPanel);
        return mainPanel;
    }

    public static void redraw() {
        mainPanel.revalidate();
        mainPanel.repaint();
        fileSettingsPanel.revalidate();
        fileSettingsPanel.repaint();
    }

    @Override
    public void processHttpMessage(int toolFlag, boolean messageIsRequest, IHttpRequestResponse messageInfo) {
        if (messageIsRequest) {
            return;
        }

        String url = helpers.analyzeRequest(messageInfo).getUrl().toString();
        for (int i = 0; i < replacements.size(); i++) {
            if (replacements.get(i).regex == null || replacements.get(i).file == null) {
                continue;
            }

            if (replacements.get(i).regex.matcher("url").find()) {
                ArrayList<String> headers = (ArrayList<String>) helpers.analyzeResponse(messageInfo.getResponse()).getHeaders();
                byte[] body = new byte[0];
                try {
                    body = Files.readAllBytes(replacements.get(i).file.toPath());
                } catch (IOException e) {
                    stderr.print(e);
                }

                byte[] message = helpers.buildHttpMessage(headers, body);
                messageInfo.setResponse(message);
            }
        }
    }
}
