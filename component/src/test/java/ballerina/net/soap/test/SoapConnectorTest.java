package ballerina.net.soap.test;

import org.ballerinalang.launcher.util.BCompileUtil;
import org.ballerinalang.launcher.util.BRunUtil;
import org.ballerinalang.launcher.util.CompileResult;
import org.ballerinalang.model.types.BEnumType;
import org.ballerinalang.model.types.BStringType;
import org.ballerinalang.model.types.BStructType;
import org.ballerinalang.model.values.BString;
import org.ballerinalang.model.values.BValue;
import org.ballerinalang.model.values.BXMLItem;
import org.testng.Assert;
import org.testng.annotations.BeforeClass;
import org.testng.annotations.Test;

public class SoapConnectorTest {
    private CompileResult compileResult;

    @BeforeClass
    public void setup() {
        compileResult = BCompileUtil.compile("test-src/test/soap-connector-test.bal");
    }

    @Test(description = "Test Soap11 request creation")
    public void testSoap11Request() {
        final String xmlBody = "<hello>world</hello>";
        final String soapAction = "hello";
        BValue[] args = { new BXMLItem(xmlBody), new BString(soapAction)};
        BValue[] returns = BRunUtil.invoke(compileResult, "testSoap11", args);

        returns[0].stringValue();
        Assert.assertEquals(returns.length, 3);
        Assert.assertEquals(returns[0].getType().getClass(), BStructType.class);
        Assert.assertEquals(returns[1].getType().getClass(), BEnumType.class);
        Assert.assertEquals(returns[2].getType().getClass(), BStringType.class);
        Assert.assertEquals(returns[2].stringValue(), soapAction);
    }
}
