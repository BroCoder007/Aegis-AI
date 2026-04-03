import { useState, useCallback } from 'react';
import { motion } from 'framer-motion';
import { Upload, Shield } from 'lucide-react';
import { invoke } from '@tauri-apps/api/core';

interface DropzoneProps {
  onScanStart: (scanId: string, fileName: string) => void;
}

export function Dropzone({ onScanStart }: DropzoneProps) {
  const [isDragActive, setIsDragActive] = useState(false);
  const [isError, setIsError] = useState('');

  const onDragEnter = useCallback((e: React.DragEvent) => {
    e.preventDefault();
    e.stopPropagation();
    setIsDragActive(true);
  }, []);

  const onDragLeave = useCallback((e: React.DragEvent) => {
    e.preventDefault();
    e.stopPropagation();
    setIsDragActive(false);
  }, []);

  const onDrop = useCallback(async (e: React.DragEvent) => {
    e.preventDefault();
    e.stopPropagation();
    setIsDragActive(false);
    setIsError('');

    if (e.dataTransfer.files && e.dataTransfer.files.length > 0) {
      const file = e.dataTransfer.files[0];
      try {
        // Since browsers don't give the full path due to security reasons,
        // Tauri apps typically handle file dropping specifically through Tauri APIs
        // to get the actual file path. For now, we'll pass the name as a mock.
        // In a real app we would use tauri-plugin-dialog or tauri window events.
        const mockPath = `C:\\Users\\Mock\\Downloads\\${file.name}`;
        
        const scanId: string = await invoke('start_scan', { filePath: mockPath });
        onScanStart(scanId, file.name);
      } catch (err) {
         setIsError(String(err));
      }
    }
  }, [onScanStart]);

  const triggerFileInput = () => {
    const el = document.getElementById('file-upload') as HTMLInputElement;
    if (el) el.click();
  };

  const handleFileChange = async (e: React.ChangeEvent<HTMLInputElement>) => {
    setIsError('');
    if (e.target.files && e.target.files.length > 0) {
      const file = e.target.files[0];
      try {
        const mockPath = `C:\\Users\\Mock\\Downloads\\${file.name}`;
        const scanId: string = await invoke('start_scan', { filePath: mockPath });
        onScanStart(scanId, file.name);
      } catch (err) {
         setIsError(String(err));
      }
    }
  };

  return (
    <motion.div
      className={`border-2 border-dashed rounded-xl p-12 flex flex-col items-center justify-center cursor-pointer transition-colors ${
        isDragActive ? 'border-blue-500 bg-blue-500/10' : 'border-gray-600 hover:border-gray-500 bg-gray-800'
      }`}
      onDragEnter={onDragEnter}
      onDragOver={onDragEnter}
      onDragLeave={onDragLeave}
      onDrop={onDrop}
      onClick={triggerFileInput}
      whileHover={{ scale: 1.02 }}
      whileTap={{ scale: 0.98 }}
    >
      <input 
        id="file-upload" 
        type="file" 
        className="hidden" 
        onChange={handleFileChange} 
      />
      <div className="bg-gray-700/50 p-4 rounded-full mb-4">
        <Shield className="w-12 h-12 text-blue-400" />
      </div>
      <h2 className="text-xl font-semibold mb-2">
        {isDragActive ? 'Drop file to scan' : 'Drag & drop a file to scan'}
      </h2>
      <p className="text-gray-400 text-sm flex items-center gap-2">
        <Upload className="w-4 h-4" />
        Supports executables, scripts, and documents
      </p>
      {isError && (
        <p className="text-red-400 mt-4 text-sm bg-red-400/10 p-2 rounded w-full text-center">
          Error starting scan: {isError}
        </p>
      )}
    </motion.div>
  );
}
