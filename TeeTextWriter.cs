using System.Text;

namespace IocEnrichmentEngine;

internal sealed class TeeTextWriter : TextWriter
{
    private readonly TextWriter primarySink;

    private readonly StringBuilder captureBuffer;

    public TeeTextWriter(TextWriter primarySink)
    {
        this.primarySink = primarySink;
        this.captureBuffer = new StringBuilder();
    }

    public string Captured => captureBuffer.ToString();

    public override Encoding Encoding => Encoding.UTF8;

    public override void Write(char value)
    {
        primarySink.Write(value);
        captureBuffer.Append(value);
    }

    public override void Write(char[] buffer, int index, int count)
    {
        primarySink.Write(buffer, index, count);
        captureBuffer.Append(buffer, index, count);
    }

    public override void Write(string? value)
    {
        primarySink.Write(value);
        captureBuffer.Append(value);
    }

    public override void WriteLine()
    {
        primarySink.WriteLine();
        captureBuffer.AppendLine();
    }

    public override void WriteLine(string? value)
    {
        primarySink.WriteLine(value);
        captureBuffer.AppendLine(value);
    }
}