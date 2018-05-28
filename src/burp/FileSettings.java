package burp;

import javax.swing.*;
import javax.swing.border.Border;
import javax.swing.border.CompoundBorder;
import javax.swing.border.EmptyBorder;
import java.awt.*;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.awt.event.FocusEvent;
import java.awt.event.FocusListener;
import java.io.File;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.regex.Pattern;

public class FileSettings extends JPanel {
    public JPanel panel;
    public File file;
    public Pattern regex;
    public JTextField fileField;
    public JTextField regexField;

    public FileSettings(File f, Pattern p) {
        this.regex = p;
        this.file = f;
        this.createPanel();
    }

    private void createPanel() {
        this.panel = new JPanel();
        this.panel.setLayout(new GridBagLayout());
        Border border = BorderFactory.createLineBorder(Color.GRAY);
        Border margin = new EmptyBorder(3, 10, 3, 10);
        this.panel.setBorder(new CompoundBorder(margin, border));

        // Setup constraints
        GridBagConstraints c = new GridBagConstraints();
        c.anchor = GridBagConstraints.NORTHWEST;
        c.insets = new Insets(3,10,3,10);
        c.weightx = 0.5;
        c.weighty = 0.5;

        // The labels on the top row
        c.gridx = 0;
        c.gridy = 0;
        JLabel regexLabel = new JLabel();
        regexLabel.setText("Match:");
        this.panel.add(regexLabel, c);

        c.gridx = 1;
        JLabel fileLabel = new JLabel();
        fileLabel.setText("File:");
        this.panel.add(fileLabel, c);

        // Text boxes on the second row
        c.gridx = 0;
        c.gridy = 1;
        c.fill = GridBagConstraints.HORIZONTAL;
        this.regexField = new JTextField();
        this.regexField.addFocusListener(new RegexFieldFocusAdapter(this));
        this.panel.add(this.regexField, c);

        c.gridx = 1;
        this.fileField = new JTextField();
        this.fileField.addFocusListener(new FileFieldFocusAdapter(this));
        this.panel.add(this.fileField, c);

        // Close button
        c.gridx = 2;
        c.gridy = 0;
        c.weightx = 0;
        c.insets = new Insets(3, 0, 3, 10);
        JButton closeButton = new JButton();
        closeButton.setText("x");
        closeButton.setToolTipText("Remove replacement");
        closeButton.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent actionEvent) {
                JButton b = (JButton)actionEvent.getSource();
                JPanel settingsPanel = (JPanel)b.getParent();
                BurpExtender.removeFile(settingsPanel);
                BurpExtender.redraw();
            }
        });

        this.panel.add(closeButton, c);

        // File chooser button
        c.gridx = 2;
        c.gridy = 1;
        c.weightx = 0;
        JButton fileChooesrButton = new JButton();
        fileChooesrButton.setText("...");
        fileChooesrButton.setToolTipText("Select file to load");
        fileChooesrButton.addActionListener(new FileChooseButtonListener(this));
        this.panel.add(fileChooesrButton, c);
    }

    private class FileChooseButtonListener implements ActionListener {
        private FileSettings fileSettings;

        public FileChooseButtonListener(FileSettings fs) {
            this.fileSettings = fs;
        }

        @Override
        public void actionPerformed(ActionEvent actionEvent) {
            JFileChooser jfc = new JFileChooser();
            int retVal = jfc.showOpenDialog(null);
            if (retVal == JFileChooser.APPROVE_OPTION) {
                java.io.File selectedFile = jfc.getSelectedFile();
                this.fileSettings.fileField.setText(selectedFile.getAbsolutePath());
                this.fileSettings.file = selectedFile;
                BurpExtender.redraw();
            }
        }
    }

    private class  FileFieldFocusAdapter implements FocusListener {
        private FileSettings fileSettings;

        public FileFieldFocusAdapter(FileSettings fs) {
            this.fileSettings = fs;
        }

        private void validatePath() {
            Path p = Paths.get(this.fileSettings.fileField.getText());
            if (p.toFile().exists()) {
                this.fileSettings.file = p.toFile();
            } else {
                this.fileSettings.fileField = null;
            }
        }

        @Override
        public void focusGained(FocusEvent focusEvent) {
        }

        @Override
        public void focusLost(FocusEvent focusEvent) {
            this.validatePath();
        }
    }

    private class RegexFieldFocusAdapter implements FocusListener {
        private FileSettings fileSettings;

        public RegexFieldFocusAdapter(FileSettings fs) {
            this.fileSettings = fs;
        }

        private void validateRegex() {
            String regexStr = this.fileSettings.regexField.getText();
            try {
                Pattern p = Pattern.compile(regexStr);
                this.fileSettings.regex = p;
            } catch (Exception e) {
                this.fileSettings.regex = null;
            }
        }

        @Override
        public void focusGained(FocusEvent focusEvent) {
        }

        @Override
        public void focusLost(FocusEvent focusEvent) {
            this.validateRegex();
        }
    }
}
