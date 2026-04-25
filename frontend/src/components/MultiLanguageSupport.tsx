import React, { useState } from 'react';

interface Language {
  code: string;
  name: string;
  flag: string;
  translations: Record<string, string>;
}

const MultiLanguageSupport: React.FC = () => {
  const [selectedLanguage, setSelectedLanguage] = useState<string>('en');
  const [showLanguageSelector, setShowLanguageSelector] = useState<boolean>(false);

  const languages: Language[] = [
    {
      code: 'en',
      name: 'English',
      flag: '🇺🇸',
      translations: {
        'compliance_dashboard': 'NIS2 Compliance Dashboard',
        'overall_compliance': 'Overall Compliance',
        'risk_management': 'Risk Management',
        'incident_handling': 'Incident Handling',
        'business_continuity': 'Business Continuity',
        'access_control': 'Access Control',
        'asset_management': 'Asset Management',
        'compliant': 'Compliant',
        'non_compliant': 'Non-Compliant',
        'partially_compliant': 'Partially Compliant',
        'not_assessed': 'Not Assessed',
        'high_priority': 'High Priority',
        'medium_priority': 'Medium Priority',
        'low_priority': 'Low Priority',
        'generate_report': 'Generate Report',
        'send_notification': 'Send Notification',
        'view_analytics': 'View Analytics'
      }
    },
    {
      code: 'tr',
      name: 'Türkçe',
      flag: '🇹🇷',
      translations: {
        'compliance_dashboard': 'NIS2 Uyumluluk Paneli',
        'overall_compliance': 'Genel Uyumluluk',
        'risk_management': 'Risk Yönetimi',
        'incident_handling': 'Olay Yönetimi',
        'business_continuity': 'İş Sürekliliği',
        'access_control': 'Erişim Kontrolü',
        'asset_management': 'Varlık Yönetimi',
        'compliant': 'Uyumlu',
        'non_compliant': 'Uyumsuz',
        'partially_compliant': 'Kısmen Uyumlu',
        'not_assessed': 'Değerlendirilmedi',
        'high_priority': 'Yüksek Öncelik',
        'medium_priority': 'Orta Öncelik',
        'low_priority': 'Düşük Öncelik',
        'generate_report': 'Rapor Oluştur',
        'send_notification': 'Bildirim Gönder',
        'view_analytics': 'Analitikleri Görüntüle'
      }
    },
    {
      code: 'de',
      name: 'Deutsch',
      flag: '🇩🇪',
      translations: {
        'compliance_dashboard': 'NIS2-Compliance-Dashboard',
        'overall_compliance': 'Gesamt-Compliance',
        'risk_management': 'Risikomanagement',
        'incident_handling': 'Vorfallbehandlung',
        'business_continuity': 'Geschäftskontinuität',
        'access_control': 'Zugangskontrolle',
        'asset_management': 'Asset-Management',
        'compliant': 'Konform',
        'non_compliant': 'Nicht konform',
        'partially_compliant': 'Teilweise konform',
        'not_assessed': 'Nicht bewertet',
        'high_priority': 'Hohe Priorität',
        'medium_priority': 'Mittlere Priorität',
        'low_priority': 'Niedrige Priorität',
        'generate_report': 'Bericht generieren',
        'send_notification': 'Benachrichtigung senden',
        'view_analytics': 'Analytik anzeigen'
      }
    },
    {
      code: 'fr',
      name: 'Français',
      flag: '🇫🇷',
      translations: {
        'compliance_dashboard': 'Tableau de Bord de Conformité NIS2',
        'overall_compliance': 'Conformité Globale',
        'risk_management': 'Gestion des Risques',
        'incident_handling': 'Gestion des Incidents',
        'business_continuity': 'Continuité d\'Activité',
        'access_control': 'Contrôle d\'Accès',
        'asset_management': 'Gestion des Actifs',
        'compliant': 'Conforme',
        'non_compliant': 'Non Conforme',
        'partially_compliant': 'Partiellement Conforme',
        'not_assessed': 'Non Évalué',
        'high_priority': 'Priorité Élevée',
        'medium_priority': 'Priorité Moyenne',
        'low_priority': 'Priorité Faible',
        'generate_report': 'Générer un Rapport',
        'send_notification': 'Envoyer une Notification',
        'view_analytics': 'Voir les Analytiques'
      }
    },
    {
      code: 'es',
      name: 'Español',
      flag: '🇪🇸',
      translations: {
        'compliance_dashboard': 'Panel de Cumplimiento NIS2',
        'overall_compliance': 'Cumplimiento General',
        'risk_management': 'Gestión de Riesgos',
        'incident_handling': 'Gestión de Incidentes',
        'business_continuity': 'Continuidad del Negocio',
        'access_control': 'Control de Acceso',
        'asset_management': 'Gestión de Activos',
        'compliant': 'Cumpliente',
        'non_compliant': 'No Cumpliente',
        'partially_compliant': 'Parcialmente Cumpliente',
        'not_assessed': 'No Evaluado',
        'high_priority': 'Alta Prioridad',
        'medium_priority': 'Prioridad Media',
        'low_priority': 'Baja Prioridad',
        'generate_report': 'Generar Informe',
        'send_notification': 'Enviar Notificación',
        'view_analytics': 'Ver Analíticas'
      }
    },
    {
      code: 'it',
      name: 'Italiano',
      flag: '🇮🇹',
      translations: {
        'compliance_dashboard': 'Dashboard di Conformità NIS2',
        'overall_compliance': 'Conformità Generale',
        'risk_management': 'Gestione del Rischio',
        'incident_handling': 'Gestione degli Incidenti',
        'business_continuity': 'Continuità Aziendale',
        'access_control': 'Controllo degli Accessi',
        'asset_management': 'Gestione degli Asset',
        'compliant': 'Conforme',
        'non_compliant': 'Non Conforme',
        'partially_compliant': 'Parzialmente Conforme',
        'not_assessed': 'Non Valutato',
        'high_priority': 'Alta Priorità',
        'medium_priority': 'Priorità Media',
        'low_priority': 'Bassa Priorità',
        'generate_report': 'Genera Report',
        'send_notification': 'Invia Notifica',
        'view_analytics': 'Visualizza Analitiche'
      }
    }
  ];

  const currentLanguage = languages.find(lang => lang.code === selectedLanguage) || languages[0];

  const translate = (key: string): string => {
    return currentLanguage.translations[key] || key;
  };

  const LanguageSelector = () => (
    <div className="absolute top-full right-0 mt-2 w-64 bg-white border border-gray-200 rounded-lg shadow-lg z-50">
      <div className="p-4">
        <h3 className="text-sm font-medium text-gray-900 mb-3">Select Language</h3>
        <div className="space-y-2">
          {languages.map((language) => (
            <button
              key={language.code}
              onClick={() => {
                setSelectedLanguage(language.code);
                setShowLanguageSelector(false);
              }}
              className={`w-full flex items-center space-x-3 px-3 py-2 rounded-md text-left hover:bg-gray-50 ${
                selectedLanguage === language.code ? 'bg-blue-50 text-blue-700' : 'text-gray-700'
              }`}
            >
              <span className="text-lg">{language.flag}</span>
              <span className="font-medium">{language.name}</span>
              {selectedLanguage === language.code && (
                <span className="ml-auto text-blue-600">✓</span>
              )}
            </button>
          ))}
        </div>
      </div>
    </div>
  );

  return (
    <div className="space-y-6">
      {/* Language Selector */}
      <div className="bg-white shadow-lg rounded-lg p-6">
        <div className="flex justify-between items-center mb-4">
          <h2 className="text-xl font-semibold text-gray-900">Language Settings</h2>
          <div className="relative">
            <button
              onClick={() => setShowLanguageSelector(!showLanguageSelector)}
              className="flex items-center space-x-2 px-4 py-2 border border-gray-300 rounded-md hover:bg-gray-50"
            >
              <span className="text-lg">{currentLanguage.flag}</span>
              <span className="font-medium">{currentLanguage.name}</span>
              <span className="text-gray-400">▼</span>
            </button>
            {showLanguageSelector && <LanguageSelector />}
          </div>
        </div>

        {/* Translation Preview */}
        <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
          <div className="bg-gray-50 p-4 rounded-lg">
            <h3 className="font-semibold text-gray-900 mb-3">Key Terms Translation</h3>
            <div className="space-y-2">
              <div className="flex justify-between">
                <span className="text-sm text-gray-600">Compliance Dashboard:</span>
                <span className="text-sm font-medium">{translate('compliance_dashboard')}</span>
              </div>
              <div className="flex justify-between">
                <span className="text-sm text-gray-600">Risk Management:</span>
                <span className="text-sm font-medium">{translate('risk_management')}</span>
              </div>
              <div className="flex justify-between">
                <span className="text-sm text-gray-600">Incident Handling:</span>
                <span className="text-sm font-medium">{translate('incident_handling')}</span>
              </div>
              <div className="flex justify-between">
                <span className="text-sm text-gray-600">Access Control:</span>
                <span className="text-sm font-medium">{translate('access_control')}</span>
              </div>
              <div className="flex justify-between">
                <span className="text-sm text-gray-600">Compliant:</span>
                <span className="text-sm font-medium">{translate('compliant')}</span>
              </div>
              <div className="flex justify-between">
                <span className="text-sm text-gray-600">Non-Compliant:</span>
                <span className="text-sm font-medium">{translate('non_compliant')}</span>
              </div>
            </div>
          </div>

          <div className="bg-gray-50 p-4 rounded-lg">
            <h3 className="font-semibold text-gray-900 mb-3">Action Buttons</h3>
            <div className="space-y-3">
              <button className="w-full bg-blue-500 text-white px-4 py-2 rounded-md hover:bg-blue-600">
                {translate('generate_report')}
              </button>
              <button className="w-full bg-green-500 text-white px-4 py-2 rounded-md hover:bg-green-600">
                {translate('send_notification')}
              </button>
              <button className="w-full bg-purple-500 text-white px-4 py-2 rounded-md hover:bg-purple-600">
                {translate('view_analytics')}
              </button>
            </div>
          </div>
        </div>
      </div>

      {/* Regional Compliance Requirements */}
      <div className="bg-white shadow-lg rounded-lg p-6">
        <h2 className="text-xl font-semibold text-gray-900 mb-4">Regional Compliance Requirements</h2>
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
          {[
            { region: 'European Union', flag: '🇪🇺', requirements: ['NIS2 Directive', 'GDPR', 'eIDAS'] },
            { region: 'United States', flag: '🇺🇸', requirements: ['NERC CIP', 'CFATS', 'TSCA'] },
            { region: 'United Kingdom', flag: '🇬🇧', requirements: ['NIS Regulations', 'UK GDPR', 'NCSC Guidelines'] },
            { region: 'Germany', flag: '🇩🇪', requirements: ['IT-Sicherheitsgesetz', 'BSI Act', 'KRITIS'] },
            { region: 'France', flag: '🇫🇷', requirements: ['LPM', 'RGPD', 'ANSSI Guidelines'] },
            { region: 'Netherlands', flag: '🇳🇱', requirements: ['Wbni', 'GDPR', 'NCSC Framework'] }
          ].map((region, index) => (
            <div key={index} className="border border-gray-200 rounded-lg p-4">
              <div className="flex items-center space-x-2 mb-3">
                <span className="text-2xl">{region.flag}</span>
                <h3 className="font-semibold text-gray-900">{region.region}</h3>
              </div>
              <ul className="space-y-1">
                {region.requirements.map((req, reqIndex) => (
                  <li key={reqIndex} className="text-sm text-gray-600">• {req}</li>
                ))}
              </ul>
            </div>
          ))}
        </div>
      </div>

      {/* Language Statistics */}
      <div className="bg-white shadow-lg rounded-lg p-6">
        <h2 className="text-xl font-semibold text-gray-900 mb-4">Language Usage Statistics</h2>
        <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
          <div>
            <h3 className="font-semibold text-gray-900 mb-3">Most Used Languages</h3>
            <div className="space-y-3">
              {[
                { language: 'English', usage: 45, flag: '🇺🇸' },
                { language: 'German', usage: 25, flag: '🇩🇪' },
                { language: 'French', usage: 15, flag: '🇫🇷' },
                { language: 'Spanish', usage: 10, flag: '🇪🇸' },
                { language: 'Turkish', usage: 5, flag: '🇹🇷' }
              ].map((lang, index) => (
                <div key={index} className="flex items-center space-x-3">
                  <span className="text-lg">{lang.flag}</span>
                  <span className="flex-1 text-sm font-medium">{lang.language}</span>
                  <div className="flex items-center space-x-2">
                    <div className="w-24 bg-gray-200 rounded-full h-2">
                      <div 
                        className="bg-blue-500 h-2 rounded-full"
                        style={{ width: `${lang.usage}%` }}
                      ></div>
                    </div>
                    <span className="text-sm text-gray-600 w-8">{lang.usage}%</span>
                  </div>
                </div>
              ))}
            </div>
          </div>

          <div>
            <h3 className="font-semibold text-gray-900 mb-3">Translation Status</h3>
            <div className="space-y-3">
              {languages.map((lang) => (
                <div key={lang.code} className="flex items-center justify-between p-3 bg-gray-50 rounded-lg">
                  <div className="flex items-center space-x-2">
                    <span className="text-lg">{lang.flag}</span>
                    <span className="font-medium">{lang.name}</span>
                  </div>
                  <div className="flex items-center space-x-2">
                    <span className="text-sm text-gray-600">
                      {Object.keys(lang.translations).length} terms
                    </span>
                    <span className="inline-flex px-2 py-1 text-xs font-semibold rounded-full bg-green-100 text-green-800">
                      Complete
                    </span>
                  </div>
                </div>
              ))}
            </div>
          </div>
        </div>
      </div>

      {/* Export Language Pack */}
      <div className="bg-white shadow-lg rounded-lg p-6">
        <h2 className="text-xl font-semibold text-gray-900 mb-4">Export Language Pack</h2>
        <div className="space-y-4">
          <p className="text-gray-600">
            Export the current language translations for use in other applications or for translation services.
          </p>
          <div className="flex space-x-4">
            <button className="bg-blue-500 text-white px-4 py-2 rounded-md hover:bg-blue-600">
              Export JSON
            </button>
            <button className="bg-green-500 text-white px-4 py-2 rounded-md hover:bg-green-600">
              Export CSV
            </button>
            <button className="bg-purple-500 text-white px-4 py-2 rounded-md hover:bg-purple-600">
              Export Excel
            </button>
          </div>
        </div>
      </div>
    </div>
  );
};

export default MultiLanguageSupport; 