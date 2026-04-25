import React, { useState } from 'react';

interface NotificationTemplate {
  id: string;
  name: string;
  subject: string;
  body: string;
  type: 'compliance_change' | 'assessment_due' | 'critical_finding' | 'remediation_complete';
}

interface NotificationRule {
  id: string;
  name: string;
  condition: string;
  template: string;
  recipients: string[];
  enabled: boolean;
}

const EmailNotifications: React.FC = () => {
  const [selectedTemplate, setSelectedTemplate] = useState<string>('');
  const [recipients, setRecipients] = useState<string>('');
  const [customSubject, setCustomSubject] = useState<string>('');
  const [customBody, setCustomBody] = useState<string>('');

  const notificationTemplates: NotificationTemplate[] = [
    {
      id: 'compliance_change',
      name: 'Compliance Status Change',
      subject: 'NIS2 Compliance Status Update - {date}',
      body: `Dear {recipient},

This is an automated notification regarding NIS2 compliance status changes.

Current Compliance Score: {score}%
Previous Score: {previousScore}%

Changes Detected:
{changes}

Please review the compliance dashboard for detailed information.

Best regards,
OTShield Compliance Team`,
      type: 'compliance_change'
    },
    {
      id: 'assessment_due',
      name: 'Assessment Due Reminder',
      subject: 'NIS2 Compliance Assessment Due - {dueDate}',
      body: `Dear {recipient},

This is a reminder that your NIS2 compliance assessment is due on {dueDate}.

Current Status:
- Last Assessment: {lastAssessment}
- Next Assessment Due: {dueDate}
- Days Remaining: {daysRemaining}

Please ensure all required documentation and evidence are prepared.

Best regards,
OTShield Compliance Team`,
      type: 'assessment_due'
    },
    {
      id: 'critical_finding',
      name: 'Critical Finding Alert',
      subject: 'URGENT: Critical NIS2 Compliance Finding',
      body: `Dear {recipient},

A critical NIS2 compliance finding has been identified that requires immediate attention.

Finding Details:
- Requirement: {requirement}
- Priority: {priority}
- Risk Level: {riskLevel}
- Description: {description}

Recommended Actions:
{recommendations}

Please address this issue within {timeline} to maintain compliance.

Best regards,
OTShield Compliance Team`,
      type: 'critical_finding'
    },
    {
      id: 'remediation_complete',
      name: 'Remediation Complete',
      subject: 'NIS2 Compliance Remediation Completed',
      body: `Dear {recipient},

A NIS2 compliance remediation task has been completed successfully.

Completion Details:
- Requirement: {requirement}
- Completed By: {completedBy}
- Completion Date: {completionDate}
- Evidence: {evidence}

Updated Compliance Score: {newScore}%

Thank you for your prompt action.

Best regards,
OTShield Compliance Team`,
      type: 'remediation_complete'
    }
  ];

  const notificationRules: NotificationRule[] = [
    {
      id: '1',
      name: 'Compliance Score Drop',
      condition: 'When compliance score drops below 70%',
      template: 'compliance_change',
      recipients: ['compliance@company.com', 'security@company.com'],
      enabled: true
    },
    {
      id: '2',
      name: 'Critical Finding',
      condition: 'When high-priority non-compliance is detected',
      template: 'critical_finding',
      recipients: ['compliance@company.com', 'security@company.com', 'management@company.com'],
      enabled: true
    },
    {
      id: '3',
      name: 'Assessment Due',
      condition: '7 days before assessment due date',
      template: 'assessment_due',
      recipients: ['compliance@company.com'],
      enabled: true
    },
    {
      id: '4',
      name: 'Remediation Complete',
      condition: 'When remediation task is marked complete',
      template: 'remediation_complete',
      recipients: ['compliance@company.com', 'security@company.com'],
      enabled: false
    }
  ];

  const sendTestEmail = () => {
    const template = notificationTemplates.find(t => t.id === selectedTemplate);
    if (!template) return;

    const emailData = {
      to: recipients.split(',').map(r => r.trim()),
      subject: customSubject || template.subject.replace('{date}', new Date().toLocaleDateString()),
      body: customBody || template.body
        .replace('{recipient}', 'Test User')
        .replace('{date}', new Date().toLocaleDateString())
        .replace('{score}', '78%')
        .replace('{previousScore}', '75%')
        .replace('{changes}', '- Risk Assessment: Non-compliant → Compliant\n- Access Control: Partially compliant → Compliant')
        .replace('{dueDate}', '2025-01-31')
        .replace('{lastAssessment}', '2024-12-15')
        .replace('{daysRemaining}', '15')
        .replace('{requirement}', 'Risk Assessment')
        .replace('{priority}', 'High')
        .replace('{riskLevel}', 'Critical')
        .replace('{description}', 'Missing annual risk assessment documentation')
        .replace('{recommendations}', '1. Complete risk assessment\n2. Document findings\n3. Update risk register')
        .replace('{timeline}', '2 weeks')
        .replace('{completedBy}', 'John Doe')
        .replace('{completionDate}', new Date().toLocaleDateString())
        .replace('{evidence}', 'Risk assessment report uploaded')
        .replace('{newScore}', '82%')
    };

    console.log('Sending test email:', emailData);
    alert('Test email sent! Check console for details.');
  };

  return (
    <div className="space-y-6">
      {/* Notification Templates */}
      <div className="bg-white shadow-lg rounded-lg p-6">
        <h2 className="text-xl font-semibold text-gray-900 mb-4">Email Templates</h2>
        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
          {notificationTemplates.map((template) => (
            <div key={template.id} className="border border-gray-200 rounded-lg p-4">
              <h3 className="font-semibold text-gray-900 mb-2">{template.name}</h3>
              <p className="text-sm text-gray-600 mb-2">{template.subject}</p>
              <p className="text-xs text-gray-500 mb-3">{template.body.substring(0, 100)}...</p>
              <button
                onClick={() => {
                  setSelectedTemplate(template.id);
                  setCustomSubject(template.subject);
                  setCustomBody(template.body);
                }}
                className="text-blue-600 hover:text-blue-800 text-sm font-medium"
              >
                Use Template
              </button>
            </div>
          ))}
        </div>
      </div>

      {/* Send Test Email */}
      <div className="bg-white shadow-lg rounded-lg p-6">
        <h2 className="text-xl font-semibold text-gray-900 mb-4">Send Test Email</h2>
        <div className="space-y-4">
          <div>
            <label className="block text-sm font-medium text-gray-700 mb-2">Template</label>
            <select
              value={selectedTemplate}
              onChange={(e) => setSelectedTemplate(e.target.value)}
              className="w-full border border-gray-300 rounded-md px-3 py-2 focus:outline-none focus:ring-2 focus:ring-blue-500"
            >
              <option value="">Select a template</option>
              {notificationTemplates.map((template) => (
                <option key={template.id} value={template.id}>{template.name}</option>
              ))}
            </select>
          </div>
          
          <div>
            <label className="block text-sm font-medium text-gray-700 mb-2">Recipients (comma-separated)</label>
            <input
              type="text"
              value={recipients}
              onChange={(e) => setRecipients(e.target.value)}
              placeholder="email1@company.com, email2@company.com"
              className="w-full border border-gray-300 rounded-md px-3 py-2 focus:outline-none focus:ring-2 focus:ring-blue-500"
            />
          </div>
          
          <div>
            <label className="block text-sm font-medium text-gray-700 mb-2">Subject</label>
            <input
              type="text"
              value={customSubject}
              onChange={(e) => setCustomSubject(e.target.value)}
              className="w-full border border-gray-300 rounded-md px-3 py-2 focus:outline-none focus:ring-2 focus:ring-blue-500"
            />
          </div>
          
          <div>
            <label className="block text-sm font-medium text-gray-700 mb-2">Body</label>
            <textarea
              value={customBody}
              onChange={(e) => setCustomBody(e.target.value)}
              rows={8}
              className="w-full border border-gray-300 rounded-md px-3 py-2 focus:outline-none focus:ring-2 focus:ring-blue-500"
            />
          </div>
          
          <button
            onClick={sendTestEmail}
            disabled={!selectedTemplate || !recipients}
            className="bg-blue-500 text-white px-4 py-2 rounded-md hover:bg-blue-600 disabled:bg-gray-300 disabled:cursor-not-allowed"
          >
            Send Test Email
          </button>
        </div>
      </div>

      {/* Notification Rules */}
      <div className="bg-white shadow-lg rounded-lg p-6">
        <h2 className="text-xl font-semibold text-gray-900 mb-4">Notification Rules</h2>
        <div className="space-y-4">
          {notificationRules.map((rule) => (
            <div key={rule.id} className="flex items-center justify-between p-4 border border-gray-200 rounded-lg">
              <div className="flex-1">
                <h3 className="font-semibold text-gray-900">{rule.name}</h3>
                <p className="text-sm text-gray-600">{rule.condition}</p>
                <p className="text-xs text-gray-500 mt-1">
                  Recipients: {rule.recipients.join(', ')}
                </p>
              </div>
              <div className="flex items-center space-x-2">
                <label className="flex items-center">
                  <input
                    type="checkbox"
                    checked={rule.enabled}
                    onChange={() => {}}
                    className="rounded border-gray-300 text-blue-600 focus:ring-blue-500"
                  />
                  <span className="ml-2 text-sm text-gray-700">Enabled</span>
                </label>
                <button className="text-blue-600 hover:text-blue-800 text-sm font-medium">
                  Edit
                </button>
              </div>
            </div>
          ))}
        </div>
      </div>

      {/* Email History */}
      <div className="bg-white shadow-lg rounded-lg p-6">
        <h2 className="text-xl font-semibold text-gray-900 mb-4">Email History</h2>
        <div className="space-y-3">
          {[
            { date: '2024-12-15 14:30', subject: 'NIS2 Compliance Status Update', recipients: 3, status: 'sent' },
            { date: '2024-12-14 09:15', subject: 'Assessment Due Reminder', recipients: 1, status: 'sent' },
            { date: '2024-12-13 16:45', subject: 'Critical Finding Alert', recipients: 4, status: 'sent' },
            { date: '2024-12-12 11:20', subject: 'Remediation Complete', recipients: 2, status: 'sent' }
          ].map((email, index) => (
            <div key={index} className="flex items-center justify-between p-3 bg-gray-50 rounded-lg">
              <div>
                <p className="font-medium text-gray-900">{email.subject}</p>
                <p className="text-sm text-gray-600">{email.date}</p>
              </div>
              <div className="text-right">
                <p className="text-sm text-gray-600">{email.recipients} recipients</p>
                <span className={`inline-flex px-2 py-1 text-xs font-semibold rounded-full ${
                  email.status === 'sent' ? 'bg-green-100 text-green-800' : 'bg-red-100 text-red-800'
                }`}>
                  {email.status}
                </span>
              </div>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
};

export default EmailNotifications; 