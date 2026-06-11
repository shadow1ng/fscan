import { useState, useEffect, useCallback } from 'react';
import { useTranslation } from 'react-i18next';
import {
  Trash2, RefreshCw, Server, Network, Cog, AlertTriangle,
  FileJson, FileSpreadsheet, List, Filter, Clock, CircleDot, Inbox,
  Download, ChevronDown
} from 'lucide-react';
import { Button } from '@/components/ui/button';
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs';
import { ScrollArea } from '@/components/ui/scroll-area';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Badge } from '@/components/ui/badge';
import { Separator } from '@/components/ui/separator';
import { Tooltip, TooltipContent, TooltipProvider, TooltipTrigger } from '@/components/ui/tooltip';
import {
  AlertDialog,
  AlertDialogAction,
  AlertDialogCancel,
  AlertDialogContent,
  AlertDialogDescription,
  AlertDialogFooter,
  AlertDialogHeader,
  AlertDialogTitle,
  AlertDialogTrigger,
} from '@/components/ui/alert-dialog';
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuTrigger,
} from '@/components/ui/dropdown-menu';
import { Skeleton } from '@/components/ui/skeleton';
import { EmptyState } from '@/components/ui/empty-state';
import { LiveFeed } from '@/components/LiveFeed';
import { ResultsChart } from '@/components/ResultsChart';
import { getResults, exportResults, clearResults, type ResultItem } from '@/lib/api';
import { useLiveFeed } from '@/contexts/LiveFeedContext';

const TYPE_ICONS = {
  host: Server,
  port: Network,
  service: Cog,
  vuln: AlertTriangle,
} as const;

export function ResultsPage() {
  const { t } = useTranslation();
  const { clearLogs } = useLiveFeed();
  const [results, setResults] = useState<ResultItem[]>([]);
  const [filter, setFilter] = useState<string>('all');
  const [loading, setLoading] = useState(false);

  const fetchResults = useCallback(async () => {
    setLoading(true);
    try {
      const data = await getResults();
      setResults(data.items);
    } catch (err) {
      console.error('Failed to fetch results:', err);
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    fetchResults();
  }, [fetchResults]);

  const handleExport = async (format: 'json' | 'csv') => {
    try {
      const blob = await exportResults(format);
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = `fscan_results.${format}`;
      a.click();
      URL.revokeObjectURL(url);
    } catch (err) {
      console.error('Failed to export:', err);
    }
  };

  const handleClear = async () => {
    try {
      await clearResults();
      setResults([]);
      clearLogs();
    } catch (err) {
      console.error('Failed to clear:', err);
    }
  };

  const getTypeIcon = (type: string) => {
    const key = type?.toLowerCase() as keyof typeof TYPE_ICONS;
    return TYPE_ICONS[key] || CircleDot;
  };

  const getTypeLabel = (type: string) => {
    switch (type?.toLowerCase()) {
      case 'host': return t('typeHost');
      case 'port': return t('typePort');
      case 'service': return t('typeService');
      case 'vuln': return t('typeVuln');
      default: return type;
    }
  };

  const filteredResults = filter === 'all'
    ? results
    : results.filter(r => r.type === filter);

  return (
    <TooltipProvider>
      <div className="grid grid-cols-1 lg:grid-cols-10 gap-4">
        {/* Left Panel - 7 cols */}
        <div className="lg:col-span-7 space-y-4">
          {/* Live Feed */}
          <LiveFeed compact showTypeLabel />

          {/* Results Panel */}
          <Card>
            <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-4">
              <CardTitle className="flex items-center gap-2 text-base">
                <List className="w-4 h-4 sm:w-5 sm:h-5 text-muted-foreground" />
                {t('resultsTitle')}
                <Badge variant="secondary" className="font-mono">
                  {filteredResults.length} {t('items')}
                </Badge>
              </CardTitle>
              <div className="flex items-center gap-1 sm:gap-2">
                <Tooltip>
                  <TooltipTrigger asChild>
                    <Button
                      variant="ghost"
                      size="sm"
                      onClick={fetchResults}
                      disabled={loading}
                      className="gap-1.5"
                    >
                      <RefreshCw className={`w-4 h-4 ${loading ? 'animate-spin' : ''}`} />
                      <span className="hidden sm:inline">{t('refresh')}</span>
                    </Button>
                  </TooltipTrigger>
                  <TooltipContent>{t('refresh')}</TooltipContent>
                </Tooltip>

                <DropdownMenu>
                  <DropdownMenuTrigger asChild>
                    <Button variant="ghost" size="sm" className="gap-1.5">
                      <Download className="w-4 h-4" />
                      <span className="hidden sm:inline">{t('export')}</span>
                      <ChevronDown className="w-3 h-3" />
                    </Button>
                  </DropdownMenuTrigger>
                  <DropdownMenuContent align="end">
                    <DropdownMenuItem onClick={() => handleExport('json')}>
                      <FileJson className="w-4 h-4 mr-2" />
                      JSON
                    </DropdownMenuItem>
                    <DropdownMenuItem onClick={() => handleExport('csv')}>
                      <FileSpreadsheet className="w-4 h-4 mr-2" />
                      CSV
                    </DropdownMenuItem>
                  </DropdownMenuContent>
                </DropdownMenu>

                <Separator orientation="vertical" className="h-5 mx-1" />

                <AlertDialog>
                  <AlertDialogTrigger asChild>
                    <Button
                      variant="ghost"
                      size="sm"
                      className="text-destructive hover:text-destructive hover:bg-destructive/10 gap-1.5"
                    >
                      <Trash2 className="w-4 h-4" />
                      <span className="hidden sm:inline">{t('clearAll')}</span>
                    </Button>
                  </AlertDialogTrigger>
                  <AlertDialogContent>
                    <AlertDialogHeader>
                      <AlertDialogTitle>{t('clearConfirmTitle')}</AlertDialogTitle>
                      <AlertDialogDescription>{t('clearConfirm')}</AlertDialogDescription>
                    </AlertDialogHeader>
                    <AlertDialogFooter>
                      <AlertDialogCancel>{t('cancel')}</AlertDialogCancel>
                      <AlertDialogAction onClick={handleClear} className="bg-destructive text-destructive-foreground hover:bg-destructive/90">
                        {t('clearAll')}
                      </AlertDialogAction>
                    </AlertDialogFooter>
                  </AlertDialogContent>
                </AlertDialog>
              </div>
            </CardHeader>

            <CardContent>
              <Tabs value={filter} onValueChange={setFilter}>
                <TabsList className="h-9 sm:h-10 p-1 bg-muted/50 mb-4">
                  <TabsTrigger value="all" className="h-7 sm:h-8 px-3 text-xs sm:text-sm gap-1.5">
                    <Filter className="w-3.5 h-3.5" />
                    {t('resultsFilterAll')}
                  </TabsTrigger>
                  <TabsTrigger value="host" className="h-7 sm:h-8 px-3 text-xs sm:text-sm gap-1.5">
                    <Server className="w-3.5 h-3.5" />
                    <span className="hidden sm:inline">{t('resultsFilterHosts')}</span>
                  </TabsTrigger>
                  <TabsTrigger value="port" className="h-7 sm:h-8 px-3 text-xs sm:text-sm gap-1.5">
                    <Network className="w-3.5 h-3.5" />
                    <span className="hidden sm:inline">{t('resultsFilterPorts')}</span>
                  </TabsTrigger>
                  <TabsTrigger value="service" className="h-7 sm:h-8 px-3 text-xs sm:text-sm gap-1.5">
                    <Cog className="w-3.5 h-3.5" />
                    <span className="hidden sm:inline">{t('resultsFilterServices')}</span>
                  </TabsTrigger>
                  <TabsTrigger value="vuln" className="h-7 sm:h-8 px-3 text-xs sm:text-sm gap-1.5">
                    <AlertTriangle className="w-3.5 h-3.5" />
                    <span className="hidden sm:inline">{t('resultsFilterVulns')}</span>
                  </TabsTrigger>
                </TabsList>

                <TabsContent value={filter} className="mt-0">
                  <ScrollArea className="h-[calc(100vh-420px)] min-h-[400px]">
                    {loading ? (
                      <div className="space-y-3 py-2">
                        {[...Array(5)].map((_, i) => (
                          <div key={i} className="flex items-start gap-3 p-3 rounded-lg border">
                            <Skeleton className="w-10 h-10 rounded-lg shrink-0" />
                            <div className="flex-1 space-y-2">
                              <div className="flex items-center gap-2">
                                <Skeleton className="h-5 w-16" />
                                <Skeleton className="h-4 w-32" />
                              </div>
                              <Skeleton className="h-4 w-48" />
                            </div>
                            <Skeleton className="h-5 w-20 shrink-0" />
                          </div>
                        ))}
                      </div>
                    ) : filteredResults.length === 0 ? (
                      <EmptyState
                        icon={Inbox}
                        title={t('resultsEmpty')}
                        description={t('resultsEmptyDescription')}
                        className="py-16"
                      />
                    ) : (
                      <div className="space-y-2">
                        {filteredResults.map((result) => {
                          const Icon = getTypeIcon(result.type);
                          const badgeVariant = result.type?.toLowerCase() as 'host' | 'port' | 'service' | 'vuln';
                          return (
                            <div
                              key={result.id}
                              className="group flex items-start gap-3 p-3 rounded-lg border bg-background hover:border-foreground/20 hover:bg-muted/30 transition-all"
                            >
                              <div className="shrink-0 w-8 h-8 sm:w-10 sm:h-10 rounded-lg flex items-center justify-center bg-muted group-hover:scale-105 transition-transform">
                                <Icon className="w-4 h-4 sm:w-5 sm:h-5 text-muted-foreground" />
                              </div>
                              <div className="flex-1 min-w-0">
                                <div className="flex items-center gap-2">
                                  <Badge variant={badgeVariant}>
                                    {getTypeLabel(result.type)}
                                  </Badge>
                                  <span className="font-mono text-sm font-medium truncate">
                                    {result.target}
                                  </span>
                                </div>
                                {result.status && (
                                  <p className="mt-1 text-sm text-muted-foreground truncate">
                                    {result.status}
                                  </p>
                                )}
                              </div>
                              <Badge variant="outline" className="shrink-0 gap-1 font-mono text-xs">
                                <Clock className="w-3 h-3" />
                                {new Date(result.time).toLocaleTimeString()}
                              </Badge>
                            </div>
                          );
                        })}
                      </div>
                    )}
                  </ScrollArea>
                </TabsContent>
              </Tabs>
            </CardContent>
          </Card>
        </div>

        {/* Right Panel - 3 cols */}
        <div className="lg:col-span-3">
          <div className="lg:sticky lg:top-20">
            <ResultsChart results={results} />
          </div>
        </div>
      </div>
    </TooltipProvider>
  );
}
