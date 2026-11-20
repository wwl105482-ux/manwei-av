using System;
using System.Drawing;
using System.Drawing.Drawing2D;
using System.Drawing.Imaging;
using System.IO;
using System.Text;

class IconGen
{
    static void Main(string[] args)
    {
        string outDir = args.Length > 0 ? args[0] : ".";
        Directory.CreateDirectory(outDir);
        int[] sizes = new int[] { 16, 20, 24, 32, 40, 48, 64, 128, 256 };
        Bitmap master = Render(1024);
        master.Save(Path.Combine(outDir, "preview.png"), ImageFormat.Png);
        byte[][] pngs = new byte[sizes.Length][];
        for (int i = 0; i < sizes.Length; i++)
        {
            using (Bitmap b = Downscale(master, sizes[i]))
            {
                using (MemoryStream ms = new MemoryStream())
                {
                    b.Save(ms, ImageFormat.Png);
                    pngs[i] = ms.ToArray();
                }
            }
        }
        WriteIco(Path.Combine(outDir, "app.ico"), sizes, pngs);
        MakeSheet(outDir);
        Console.WriteLine("icon written: " + Path.Combine(outDir, "app.ico"));
    }

    static Bitmap Downscale(Bitmap src, int size)
    {
        Bitmap b = new Bitmap(size, size, PixelFormat.Format32bppArgb);
        using (Graphics g = Graphics.FromImage(b))
        {
            g.Clear(Color.Transparent);
            g.InterpolationMode = InterpolationMode.HighQualityBicubic;
            g.PixelOffsetMode = PixelOffsetMode.HighQuality;
            g.SmoothingMode = SmoothingMode.HighQuality;
            g.CompositingQuality = CompositingQuality.HighQuality;
            g.DrawImage(src, new Rectangle(0, 0, size, size), new Rectangle(0, 0, src.Width, src.Height), GraphicsUnit.Pixel);
        }
        return b;
    }

    static GraphicsPath RoundRect(float x, float y, float w, float h, float r)
    {
        GraphicsPath p = new GraphicsPath();
        p.AddArc(x, y, r * 2, r * 2, 180, 90);
        p.AddArc(x + w - r * 2, y, r * 2, r * 2, 270, 90);
        p.AddArc(x + w - r * 2, y + h - r * 2, r * 2, r * 2, 0, 90);
        p.AddArc(x, y + h - r * 2, r * 2, r * 2, 90, 90);
        p.CloseFigure();
        return p;
    }

    static GraphicsPath Shield(float cx, float top, float w, float h)
    {
        GraphicsPath p = new GraphicsPath();
        float x0 = cx - w / 2f, x1 = cx + w / 2f;
        float y0 = top, yb = top + h;
        p.AddLine(cx, y0, x1, y0 + h * 0.07f);
        p.AddBezier(x1, y0 + h * 0.07f, x1, y0 + h * 0.45f, x1 - w * 0.13f, y0 + h * 0.78f, cx, yb);
        p.AddBezier(cx, yb, x0 + w * 0.13f, y0 + h * 0.78f, x0, y0 + h * 0.45f, x0, y0 + h * 0.07f);
        p.AddLine(x0, y0 + h * 0.07f, cx, y0);
        p.CloseFigure();
        return p;
    }

    static Bitmap Render(int S)
    {
        Bitmap bmp = new Bitmap(S, S, PixelFormat.Format32bppArgb);
        using (Graphics g = Graphics.FromImage(bmp))
        {
            g.Clear(Color.Transparent);
            g.SmoothingMode = SmoothingMode.AntiAlias;
            g.InterpolationMode = InterpolationMode.HighQualityBicubic;
            g.PixelOffsetMode = PixelOffsetMode.HighQuality;

            float pad = S * 0.045f;
            float r = S * 0.235f;
            RectangleF box = new RectangleF(pad, pad, S - pad * 2, S - pad * 2);

            // badge background gradient
            using (GraphicsPath bg = RoundRect(box.X, box.Y, box.Width, box.Height, r))
            {
                using (LinearGradientBrush lg = new LinearGradientBrush(new PointF(0, 0), new PointF(S, S), Color.FromArgb(255, 56, 132, 255), Color.FromArgb(255, 18, 48, 130)))
                {
                    lg.SetSigmaBellShape(0.35f, 1f);
                    g.FillPath(lg, bg);
                }
                using (GraphicsPath inner = RoundRect(box.X + S * 0.012f, box.Y + S * 0.012f, box.Width - S * 0.024f, box.Height - S * 0.024f, r * 0.92f))
                {
                    using (Pen pen = new Pen(Color.FromArgb(70, 255, 255, 255), S * 0.012f))
                    {
                        g.DrawPath(pen, inner);
                    }
                }
            }

            // soft top gloss
            using (GraphicsPath gloss = new GraphicsPath())
            {
                gloss.AddEllipse(-S * 0.15f, -S * 0.55f, S * 1.3f, S * 0.95f);
                using (PathGradientBrush pg = new PathGradientBrush(gloss))
                {
                    pg.CenterColor = Color.FromArgb(90, 255, 255, 255);
                    pg.SurroundColors = new Color[] { Color.FromArgb(0, 255, 255, 255) };
                    g.FillPath(pg, gloss);
                }
            }

            float sw = S * 0.50f;
            float sh = S * 0.60f;
            float stop = S * 0.185f;
            float scx = S * 0.5f;

            // shield shadow
            using (GraphicsPath shp = Shield(scx + S * 0.012f, stop + S * 0.022f, sw, sh))
            {
                using (SolidBrush sb = new SolidBrush(Color.FromArgb(55, 3, 10, 40)))
                {
                    g.FillPath(sb, shp);
                }
            }

            // shield body
            using (GraphicsPath shp = Shield(scx, stop, sw, sh))
            {
                using (LinearGradientBrush sg = new LinearGradientBrush(new PointF(0, stop), new PointF(0, stop + sh), Color.FromArgb(255, 255, 255, 255), Color.FromArgb(255, 210, 226, 255)))
                {
                    g.FillPath(sg, shp);
                }
                using (Pen edge = new Pen(Color.FromArgb(60, 120, 160, 230), S * 0.010f))
                {
                    g.DrawPath(edge, shp);
                }
            }

            // check mark
            PointF[] pts = new PointF[]
            {
                new PointF(scx - S * 0.115f, stop + sh * 0.50f),
                new PointF(scx - S * 0.025f, stop + sh * 0.62f),
                new PointF(scx + S * 0.135f, stop + sh * 0.36f)
            };
            using (GraphicsPath ck = new GraphicsPath())
            {
                ck.AddCurve(pts, 0.0f);
                using (Pen cp = new Pen(Color.FromArgb(255, 34, 197, 94), S * 0.085f))
                {
                    cp.StartCap = LineCap.Round;
                    cp.EndCap = LineCap.Round;
                    cp.LineJoin = LineJoin.Round;
                    g.DrawPath(cp, ck);
                }
            }
        }
        return bmp;
    }

    static void MakeSheet(string outDir)
    {
        int[] small = new int[] { 16, 24, 32, 48 };
        int cell = 160;
        using (Bitmap sheet = new Bitmap(cell * small.Length + 20, cell + 20))
        using (Graphics g = Graphics.FromImage(sheet))
        {
            g.Clear(Color.FromArgb(245, 245, 248));
            g.InterpolationMode = InterpolationMode.NearestNeighbor;
            g.PixelOffsetMode = PixelOffsetMode.Half;
            Bitmap master = Render(1024);
            for (int i = 0; i < small.Length; i++)
            {
                using (Bitmap b = Downscale(master, small[i]))
                {
                    int scale = Math.Max(1, cell / small[i]);
                    g.DrawImage(b, new Rectangle(10 + i * cell, 10, small[i] * scale, small[i] * scale));
                }
            }
            master.Dispose();
            sheet.Save(Path.Combine(outDir, "sheet.png"), ImageFormat.Png);
        }
    }

    static void WriteIco(string path, int[] sizes, byte[][] pngs)
    {
        using (FileStream fs = new FileStream(path, FileMode.Create))
        using (BinaryWriter bw = new BinaryWriter(fs))
        {
            bw.Write((short)0);
            bw.Write((short)1);
            bw.Write((short)sizes.Length);
            int offset = 6 + 16 * sizes.Length;
            for (int i = 0; i < sizes.Length; i++)
            {
                int s = sizes[i];
                bw.Write((byte)(s >= 256 ? 0 : s));
                bw.Write((byte)(s >= 256 ? 0 : s));
                bw.Write((byte)0);
                bw.Write((byte)0);
                bw.Write((short)1);
                bw.Write((short)32);
                bw.Write(pngs[i].Length);
                bw.Write(offset);
                offset += pngs[i].Length;
            }
            for (int i = 0; i < sizes.Length; i++) bw.Write(pngs[i]);
        }
    }
}
