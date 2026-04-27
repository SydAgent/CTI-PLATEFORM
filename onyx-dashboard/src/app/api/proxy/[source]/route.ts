import { NextResponse } from 'next/server';

const SOURCES: Record<string, () => Promise<any>> = {
  cisa: async () => (await import('@/lib/connectors/cisaKev')).fetchCISAKEV(),
  gdelt: async () => (await import('@/lib/connectors/gdelt')).fetchGDELT(),
  gdeltgeo: async () => (await import('@/lib/connectors/gdeltGeo')).fetchGDELTGeo(),
  mitre: async () => (await import('@/lib/connectors/mitre')).fetchMITRE(),
  openphish: async () => (await import('@/lib/connectors/openphish')).fetchOpenPhish(),
  torexits: async () => (await import('@/lib/connectors/torExits')).fetchTorExits(),
  nvd: async () => (await import('@/lib/connectors/nvd')).fetchNVD(),
  circl: async () => (await import('@/lib/connectors/circlMisp')).fetchCIRCLFeed(20),
  reliefweb: async () => (await import('@/lib/connectors/reliefweb')).fetchReliefWeb(),
  urlhaus: async () => (await import('@/lib/connectors/urlhaus')).fetchURLhaus(),
  threatfox: async () => (await import('@/lib/connectors/threatfox')).fetchThreatfox(),
  malwarebazaar: async () => (await import('@/lib/connectors/malwarebazaar')).fetchMalwareBazaar(),
  otx: async () => (await import('@/lib/connectors/otx')).fetchOTX(),
  abuseipdb: async () => (await import('@/lib/connectors/abuseipdb')).fetchAbuseIPDB(),
  virustotal: async () => (await import('@/lib/connectors/virustotal')).fetchVirusTotal(),
};

export async function GET(request: Request, { params }: { params: { source: string } }) {
  return handleProxy(params.source);
}

export async function POST(request: Request, { params }: { params: { source: string } }) {
  return handleProxy(params.source);
}

async function handleProxy(source: string) {
  try {
    const startTime = Date.now();
    let data;
    let records = 0;

    const fetcher = SOURCES[source.toLowerCase()];
    if (fetcher) {
      data = await fetcher();
      records = Array.isArray(data) ? data.length : (data ? 1 : 0);
    } else {
      return NextResponse.json({ error: 'Unknown source' }, { status: 400 });
    }

    const duration = Date.now() - startTime;
    console.log(`[SOURCE=${source}] [STATUS=ok] [RECORDS=${records}] [DURATION=${duration}ms]`);

    return NextResponse.json(data, {
      status: 200,
      headers: {
        'Access-Control-Allow-Origin': '*',
        'Cache-Control': 's-maxage=300, stale-while-revalidate=600'
      }
    });

  } catch (error: any) {
    console.error(`[SOURCE=${source}] [STATUS=error] [ERROR=${error.message}]`);
    return NextResponse.json({ error: error.message }, { status: error.message === 'Rate limited' ? 429 : 500 });
  }
}
