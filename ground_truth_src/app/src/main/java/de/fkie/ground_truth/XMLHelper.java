package de.fkie.ground_truth;

import android.content.Context;
import java.util.*;
import java.io.*;
import javax.xml.parsers.*;
import javax.xml.transform.*;
import javax.xml.transform.dom.*;
import javax.xml.transform.stream.*;
import org.w3c.dom.*;

public class XMLHelper {

    private static final String FILE_NAME = "GroundTruth.xml";
    private Document doc;
    private Element rootElement;
    private Context context;

    public XMLHelper(Context context) {
        this.context = context;
        try {
            File xmlFile = new File(context.getFilesDir(), FILE_NAME);
            DocumentBuilderFactory dbFactory = DocumentBuilderFactory.newInstance();
            DocumentBuilder dBuilder = dbFactory.newDocumentBuilder();

            if (xmlFile.exists()) {
                doc = dBuilder.parse(xmlFile);
                rootElement = doc.getDocumentElement();
            } else {
                doc = dBuilder.newDocument();
                rootElement = doc.createElement("root");
                doc.appendChild(rootElement);
                writeXMLToFile();
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public void insertData(String value) {
        int nextId = 0;
        NodeList nodeList = rootElement.getChildNodes();
        for (int i = 0; i < nodeList.getLength(); i++) {
            Node node = nodeList.item(i);
            if (node.getNodeType() == Node.ELEMENT_NODE) {
                Element element = (Element) node;
                int id = Integer.parseInt(element.getAttribute("ID"));
                if (id >= nextId) {
                    nextId = id + 1;
                }
            }
        }
        Element newElement = doc.createElement("Element");
        newElement.setAttribute("ID", Integer.toString(nextId));
        newElement.setTextContent(value);
        rootElement.appendChild(newElement);
        writeXMLToFile();
    }


    public void deleteData() {
        NodeList nodeList = rootElement.getChildNodes();
        List<Integer> ids = new ArrayList<>();
        for (int i = 0; i < nodeList.getLength(); i++) {
            Node node = nodeList.item(i);
            if (node.getNodeType() == Node.ELEMENT_NODE) {
                Element element = (Element) node;
                ids.add(Integer.parseInt(element.getAttribute("ID")));
            }
        }
        if (!ids.isEmpty()) {
            int randomId = ids.get(new Random().nextInt(ids.size()));
            for (int i = 0; i < nodeList.getLength(); i++) {
                Node node = nodeList.item(i);
                if (node.getNodeType() == Node.ELEMENT_NODE) {
                    Element element = (Element) node;
                    if (Integer.parseInt(element.getAttribute("ID")) == randomId) {
                        rootElement.removeChild(node);
                        writeXMLToFile();
                        break;
                    }
                }
            }
        }
    }

    public void updateData(String newValue) {
        NodeList nodeList = rootElement.getChildNodes();
        List<Integer> ids = new ArrayList<>();
        for (int i = 0; i < nodeList.getLength(); i++) {
            Node node = nodeList.item(i);
            if (node.getNodeType() == Node.ELEMENT_NODE) {
                Element element = (Element) node;
                ids.add(Integer.parseInt(element.getAttribute("ID")));
            }
        }
        if (!ids.isEmpty()) {
            int randomId = ids.get(new Random().nextInt(ids.size()));
            for (int i = 0; i < nodeList.getLength(); i++) {
                Node node = nodeList.item(i);
                if (node.getNodeType() == Node.ELEMENT_NODE) {
                    Element element = (Element) node;
                    if (Integer.parseInt(element.getAttribute("ID")) == randomId) {
                        element.setTextContent(newValue);
                        writeXMLToFile();
                        break;
                    }
                }
            }
        }
    }



    public boolean doesIdExist(String id) {
        NodeList nodeList = rootElement.getChildNodes();
        for (int i = 0; i < nodeList.getLength(); i++) {
            Node node = nodeList.item(i);
            if (node.getNodeType() == Node.ELEMENT_NODE) {
                Element element = (Element) node;
                if (element.getAttribute("ID").equals(id)) {
                    return true;
                }
            }
        }
        return false;
    }


    private void writeXMLToFile() {
        try {
            TransformerFactory transformerFactory = TransformerFactory.newInstance();
            Transformer transformer = transformerFactory.newTransformer();
            DOMSource source = new DOMSource(doc);
            StreamResult result = new StreamResult(new File(context.getFilesDir(), FILE_NAME));
            transformer.transform(source, result);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}
