package burp;

import javax.swing.*;
import javax.swing.border.Border;
import javax.swing.border.CompoundBorder;
import javax.swing.border.EmptyBorder;
import java.awt.*;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.io.File;

public class FileSettings extends JPanel {
    public JPanel panel;

    public FileSettings() {
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
        JTextField regexField = new JTextField();
        this.panel.add(regexField, c);

        c.gridx = 1;
        JTextField fileField = new JTextField();
        this.panel.add(fileField, c);

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

        fileChooesrButton.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent actionEvent) {
                JFileChooser jfc = new JFileChooser();
                int retVal = jfc.showOpenDialog(null);
                if (retVal == JFileChooser.APPROVE_OPTION) {
                    File selectedFile = jfc.getSelectedFile();
                    fileField.setText(selectedFile.getAbsolutePath());
                    BurpExtender.mainPanel.revalidate();
                    BurpExtender.mainPanel.repaint();
                }
            }
        });

        this.panel.add(fileChooesrButton, c);
    }
}
