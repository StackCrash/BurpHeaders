package burp;

public class BurpExtender implements IBurpExtender
{
    private IBurpExtenderCallbacks callbacks;
    private final String version;
    private final String name;

    public BurpExtender()
    {
        this.name = "Burp Headers";
        this.version = "0.2";
    }

    @Override
    public void registerExtenderCallbacks(IBurpExtenderCallbacks callbacks)
    {
        this.callbacks = callbacks;

        callbacks.setExtensionName(this.name + " " + this.version);
        callbacks.registerScannerCheck(new BurpUtilities(this));
    }

    public IBurpExtenderCallbacks getCallbacks()
    {
        return this.callbacks;
    }
}