package org.owasp.benchmarkutils.score.parsers;

import java.io.FileInputStream;
import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import org.owasp.benchmarkutils.score.BenchmarkScore;
import org.owasp.benchmarkutils.score.ResultFile;
import org.owasp.benchmarkutils.score.TestCaseResult;
import org.owasp.benchmarkutils.score.TestSuiteResults;
import org.w3c.dom.Document;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;
import org.xml.sax.InputSource;

public class JsaReader extends Reader {

    @Override
    public boolean canRead(ResultFile resultFile) {
        System.out.println("TestcanReadJsa");
        return resultFile.filename().endsWith(".xml")
                && resultFile.xmlRootNodeName().equals("RESULT");
    }

    @Override
    public TestSuiteResults parse(ResultFile resultFile) throws Exception {
        System.out.println("TestParseJsa1");
        DocumentBuilderFactory docBuilderFactory = DocumentBuilderFactory.newInstance();
        // Prevent XXE
        docBuilderFactory.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
        DocumentBuilder docBuilder = docBuilderFactory.newDocumentBuilder();
        InputSource is = new InputSource(new FileInputStream(resultFile.file()));
        Document doc = docBuilder.parse(is);

        TestSuiteResults tr = new TestSuiteResults("JSA", false, TestSuiteResults.ToolType.SAST);

        Node root = doc.getDocumentElement();
        String version = "1.0";

        NodeList rootList = root.getChildNodes();
        for (int i = 0; i < rootList.getLength(); i++) {
            Node n = rootList.item(i);
            System.out.println("NodeName: " + n.getNodeName());
        }
        tr.setToolVersion(version);
        System.out.println("ToolVersion: " + version);

        Node Errors = rootList.item(1);
        System.out.println("Errors: " + Errors.getNodeName());
        List<Node> errorList = getNamedNodes("error", Errors.getChildNodes());
        for (Node error : errorList) {
            List<TestCaseResult> tcrs = parseJsaItem(error);
            for (TestCaseResult tcr : tcrs) {
                tr.put(tcr);
            }
        }

        return tr;
    }

    private List<TestCaseResult> parseJsaItem(Node error) throws IOException {
        System.out.println("TestParseJsaItem");
        Node detectionInfo = error.getChildNodes().item(1);
        System.out.println("DetectionInfo: " + detectionInfo.getNodeName());

        List<TestCaseResult> results = new ArrayList<TestCaseResult>();

        Node fileNameNode = getNamedNode("fileName", detectionInfo.getChildNodes());
        String filename = fileNameNode.getTextContent().trim();
        System.out.println("FileName: " + filename);
        String testclass = filename.substring(filename.lastIndexOf("\\") + 1);
        System.out.println("TestClass: " + testclass);

        Node categoryNode = getNamedChildren("category", detectionInfo).get(0);
        Node subCategoryNode = getNamedChildren("subCategory", detectionInfo).get(0);
        String rule = categoryNode.getTextContent().trim();
        String subRule = subCategoryNode.getTextContent().trim();

        System.out.println("Rule: " + rule + " SubRule: " + subRule);
        if (testclass.startsWith(BenchmarkScore.TESTCASENAME)) {
            TestCaseResult tcr = new TestCaseResult();
            tcr.setTestCaseName(testclass);
            tcr.setNumber(testNumber(testclass));
            int cwe = figureCWE(rule, subRule);
            System.out.println("CWE: " + cwe);
            tcr.setCWE(cwe);
            tcr.setCategory(rule);

            tcr.setEvidence(getNamedChild("reportLine", detectionInfo).getTextContent().trim());
            results.add(tcr);
        }
        System.out.println("result added");
        return results;
    }

    private int figureCWE(String rule, String subRule) {
        switch (rule) {
            case "SQL Injection":
                return 89;
            case "不正确输入校验":
                if (subRule.equals("跨站脚本")) return 79;
                else return 0;
            case "Invalid cleaning & validation":
                if (subRule.equals("XSS")) return 79;
                else return 0;
            default:
                return 0;
        }
    }
}
