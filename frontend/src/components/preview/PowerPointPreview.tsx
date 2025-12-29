import React, { useState, useEffect, useRef } from 'react';
import JSZip from 'jszip';
import { Loader2, Monitor, Image as ImageIcon } from 'lucide-react';

interface PowerPointPreviewProps {
    file: File | Blob | string;
}

interface Slide {
    id: string;
    index: number;
    paragraphs: string[]; // Changed from text[] to paragraphs[] to keep structure
    images: string[];
}

const PowerPointPreview: React.FC<PowerPointPreviewProps> = ({ file }) => {
    const [slides, setSlides] = useState<Slide[]>([]);
    const [loading, setLoading] = useState(true);
    const [error, setError] = useState<string | null>(null);
    const scrollContainerRef = useRef<HTMLDivElement>(null);

    useEffect(() => {
        const load = async () => {
            try {
                let data;
                if (typeof file === 'string') {
                    const res = await fetch(file, { credentials: 'include' });
                    data = await res.arrayBuffer();
                } else {
                    data = await file.arrayBuffer();
                }

                const zip = await JSZip.loadAsync(data);

                // 1. Get slide list from presentation.xml or relations
                // Simplification: We look for ppt/slides/slideX.xml files
                const slideFiles = Object.keys(zip.files).filter(path => path.match(/^ppt\/slides\/slide\d+\.xml$/));

                // Sort by number (slide1, slide2, ...)
                slideFiles.sort((a, b) => {
                    const numA = parseInt(a.match(/slide(\d+)\.xml/)![1]);
                    const numB = parseInt(b.match(/slide(\d+)\.xml/)![1]);
                    return numA - numB;
                });

                const parsedSlides: Slide[] = [];

                for (let i = 0; i < slideFiles.length; i++) {
                    const path = slideFiles[i];
                    const content = await zip.file(path)?.async("string");
                    if (!content) continue;

                    // Parse Text by Paragraphs (a:p)
                    // This preserves line structure much better than just flattening all text tokens
                    const parser = new DOMParser();
                    const xmlDoc = parser.parseFromString(content, "text/xml");
                    const paragraphsTags = xmlDoc.getElementsByTagName("a:p");

                    const slideParagraphs: string[] = [];

                    for (let p = 0; p < paragraphsTags.length; p++) {
                        const pNode = paragraphsTags[p];
                        // Get all text runs (a:t) within this paragraph
                        const textRuns = pNode.getElementsByTagName("a:t");
                        let paragraphText = "";
                        for (let t = 0; t < textRuns.length; t++) {
                            paragraphText += textRuns[t].textContent || "";
                        }

                        // Only add non-empty paragraphs to avoid too much whitespace
                        if (paragraphText.trim()) {
                            slideParagraphs.push(paragraphText);
                        }
                    }

                    // --- IMAGE EXTRACTION SUPPORT ---
                    // 1. Try to load the relationships file for this slide
                    // Path: ppt/slides/slide1.xml -> ppt/slides/_rels/slide1.xml.rels
                    const fileName = path.split('/').pop();
                    const relsPath = `ppt/slides/_rels/${fileName}.rels`;
                    const relsContent = await zip.file(relsPath)?.async("string");

                    const slideImages: string[] = [];

                    if (relsContent) {
                        const relsDoc = parser.parseFromString(relsContent, "text/xml");
                        const relationships = relsDoc.getElementsByTagName("Relationship");

                        // 2. Find all Image relationships by RId
                        // In the slide XML, images are often <a:blip r:embed="rIdX">. 
                        // For simplicity, we just grab ALL images linked in the rels file for this slide.
                        // Correct linking (placement) is hard, so we append them at the bottom or top.

                        for (let r = 0; r < relationships.length; r++) {
                            const rel = relationships[r];
                            const type = rel.getAttribute("Type");
                            if (type && type.includes("/image")) {
                                let target = rel.getAttribute("Target");
                                if (target) {
                                    // Target is often relative: "../media/image1.png" -> "ppt/media/image1.png"
                                    // Or "media/image1.png" -> "ppt/slides/media/image1.png" (unlikely)
                                    // Standard is usually sibling "media" folder of referencing parent?
                                    // Actually usually "ppt/media" is the root based `../media`.

                                    let imagePathInZip = "";
                                    if (target.startsWith("../")) {
                                        imagePathInZip = "ppt/" + target.replace("../", "");
                                    } else {
                                        // Just try to find it?
                                        imagePathInZip = "ppt/media/" + target.split('/').pop();
                                    }

                                    const imgFile = zip.file(imagePathInZip);
                                    if (imgFile) {
                                        const imgBlob = await imgFile.async("blob");
                                        const imgUrl = URL.createObjectURL(imgBlob);
                                        slideImages.push(imgUrl);
                                    }
                                }
                            }
                        }
                    }

                    parsedSlides.push({
                        id: path,
                        index: i,
                        paragraphs: slideParagraphs,
                        images: slideImages
                    });
                }

                if (parsedSlides.length === 0) {
                    setError("No content found or encrypted file.");
                } else {
                    setSlides(parsedSlides);
                }

            } catch (e) {
                console.error(e);
                setError("Failed to parse PowerPoint file.");
            } finally {
                setLoading(false);
            }
        };
        load();
    }, [file]);

    const [activeSlide, setActiveSlide] = useState(0);

    useEffect(() => {
        // Observer to track which slide is in view
        const observer = new IntersectionObserver((entries) => {
            entries.forEach((entry) => {
                if (entry.isIntersecting) {
                    const idx = parseInt(entry.target.id.replace('slide-view-', ''));
                    setActiveSlide(idx);
                }
            });
        }, {
            root: scrollContainerRef.current,
            threshold: 0.5 // Trigger when 50% of slide is visible
        });

        slides.forEach((_, idx) => {
            const el = document.getElementById(`slide-view-${idx}`);
            if (el) observer.observe(el);
        });

        return () => observer.disconnect();
    }, [slides]);

    const scrollToSlide = (index: number) => {
        const el = document.getElementById(`slide-view-${index}`);
        if (el) {
            el.scrollIntoView({ behavior: 'smooth', block: 'start' });
        }
    };

    if (loading) return <div className="flex justify-center items-center h-full"><Loader2 className="w-8 h-8 animate-spin text-purple-500" /></div>;
    if (error) return <div className="flex justify-center items-center h-full text-red-400">{error}</div>;

    return (
        <div className="flex h-full w-full bg-neutral-900 rounded-xl overflow-hidden border border-neutral-800">
            {/* Sidebar */}
            <div className="w-48 bg-neutral-950 border-r border-neutral-800 overflow-y-auto custom-scrollbar flex-shrink-0">
                <div className="p-4 text-xs font-bold text-neutral-500 uppercase tracking-wider sticky top-0 bg-neutral-950 z-10">Slides</div>
                <div className="space-y-2 p-2 pt-0">
                    {slides.map((slide, idx) => (
                        <button
                            key={slide.id}
                            onClick={() => scrollToSlide(idx)}
                            className={`w-full text-left p-3 rounded-lg text-sm transition flex items-center gap-3 outline-none ${activeSlide === idx
                                    ? 'bg-purple-600/20 text-purple-300 border border-purple-600/30'
                                    : 'hover:bg-neutral-800 text-neutral-400 border border-transparent'
                                }`}
                        >
                            <Monitor className="w-4 h-4 flex-shrink-0" />
                            <span>Slide {idx + 1}</span>
                        </button>
                    ))}
                </div>
            </div>

            {/* Main Content - Vertical Layout */}
            <div ref={scrollContainerRef} className="flex-1 overflow-auto p-4 md:p-12 custom-scrollbar bg-neutral-800/50 flex flex-col items-center gap-8">
                {slides.map((slide, idx) => (
                    <div
                        id={`slide-view-${idx}`}
                        key={slide.id}
                        className="w-full max-w-4xl bg-white shadow-2xl min-h-[500px] rounded-lg overflow-hidden flex flex-col relative shrink-0"
                    >
                        {/* Slide Header/Number */}
                        <div className="absolute top-4 right-4 text-xs font-bold text-gray-300 bg-gray-100 px-2 py-1 rounded select-none">
                            #{idx + 1}
                        </div>

                        <div className="p-12 md:p-16 flex flex-col h-full">
                            {/* Text Content */}
                            {slide.paragraphs.length > 0 && (
                                <div className="space-y-4 mb-8">
                                    {slide.paragraphs.map((text, pIdx) => (
                                        <p key={pIdx} className="text-black text-lg md:text-xl font-medium leading-relaxed break-words">
                                            {text}
                                        </p>
                                    ))}
                                </div>
                            )}

                            {/* Image Content */}
                            {slide.images.length > 0 && (
                                <div className="grid grid-cols-1 md:grid-cols-2 gap-4 mt-auto">
                                    {slide.images.map((img, imgIdx) => (
                                        <img key={imgIdx} src={img} alt={`Slide ${idx + 1} content ${imgIdx}`} className="rounded-lg border border-neutral-200 object-contain max-h-96 w-full bg-neutral-50" />
                                    ))}
                                </div>
                            )}

                            {/* Fallback for empty slides */}
                            {slide.paragraphs.length === 0 && slide.images.length === 0 && (
                                <div className="flex flex-col items-center justify-center flex-1 text-gray-300 min-h-[300px]">
                                    <ImageIcon className="w-16 h-16 mb-4 opacity-50" />
                                    <p className="text-sm">Empty Slide</p>
                                </div>
                            )}
                        </div>
                    </div>
                ))}
            </div>
        </div>
    );
};

export default PowerPointPreview;
