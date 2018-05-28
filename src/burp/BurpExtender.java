package burp;

import javax.swing.*;
import java.awt.*;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;

public class BurpExtender implements IBurpExtender, ITab {
    private static IBurpExtenderCallbacks callbacks;
    private static IExtensionHelpers helpers;
    public static JPanel mainPanel;
    public static JPanel fileSettingsPanel;
    public static int numFiles;

    @Override
    public void registerExtenderCallbacks(IBurpExtenderCallbacks _callbacks) {
        numFiles = 0;
        callbacks = _callbacks;
        helpers = callbacks.getHelpers();

        callbacks.setExtensionName("File Replacer");

        this.setupUI();
        callbacks.addSuiteTab(this);

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
                BurpExtender.addFile();
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

    private static void addFile() {
        numFiles++;
        GridBagConstraints c = new GridBagConstraints();
        c.anchor = GridBagConstraints.NORTHWEST;
        c.fill = GridBagConstraints.HORIZONTAL;
        c.weightx = 1;
        c.gridx = 0;
        c.gridy = numFiles;

        FileSettings f = new FileSettings();
        fileSettingsPanel.add(f.panel, c);
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

}
